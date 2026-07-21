import { ENTITY_KINDS, type EntityKind } from '../../api/types';
import type {
  RegistryAutoUpdateCadence,
  RegistryAutoUpdateDueItem,
  RegistryAutoUpdateSettings,
  RegistryAutoUpdateStatus,
  RegistryAutoUpdateWeekday,
} from '../../api/types';
import { entityKindLabels } from '../../api/labels';
import { useRegistryAutoUpdateDuePlan, useRequestRegistryAutoUpdate } from '../../api/hooks';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
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
  SkeletonDeflist,
  SkeletonRegion,
  Table,
  Toggle,
  useToast,
} from '../../ui';

const CADENCE_KINDS = ['interval_hours', 'daily', 'weekly'] as const;
type CadenceKind = (typeof CADENCE_KINDS)[number];

const WEEKDAYS: RegistryAutoUpdateWeekday[] = [
  'monday',
  'tuesday',
  'wednesday',
  'thursday',
  'friday',
  'saturday',
  'sunday',
];

const statusKeys: Record<RegistryAutoUpdateStatus, MessageKey> = {
  idle: 'settings.registryAutoUpdate.status.idle',
  due: 'settings.registryAutoUpdate.status.due',
  queued: 'settings.registryAutoUpdate.status.queued',
  running: 'settings.registryAutoUpdate.status.running',
  completed: 'settings.registryAutoUpdate.status.completed',
  failed: 'settings.registryAutoUpdate.status.failed',
  manual_required: 'settings.registryAutoUpdate.status.manualRequired',
};

function statusTone(
  status: RegistryAutoUpdateStatus,
): 'neutral' | 'accent' | 'warn' | 'error' | 'ok' {
  if (status === 'completed') return 'ok';
  if (status === 'failed' || status === 'manual_required') return 'warn';
  if (status === 'queued' || status === 'running' || status === 'due') return 'accent';
  return 'neutral';
}

function numberValue(value: string, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function cadenceKind(cadence: RegistryAutoUpdateCadence): CadenceKind {
  return cadence.kind;
}

function cadenceLabel(cadence: RegistryAutoUpdateCadence, t: ReturnType<typeof useT>): string {
  if (cadence.kind === 'interval_hours') {
    return t('settings.registryAutoUpdate.cadence.intervalSummary', { hours: cadence.hours });
  }
  if (cadence.kind === 'daily') {
    return t('settings.registryAutoUpdate.cadence.dailySummary', { hour: cadence.hour_utc });
  }
  return t('settings.registryAutoUpdate.cadence.weeklySummary', {
    weekday: t(`settings.registryAutoUpdate.weekday.${cadence.weekday}` as MessageKey),
    hour: cadence.hour_utc,
  });
}

function dueReason(item: RegistryAutoUpdateDueItem, t: ReturnType<typeof useT>): string {
  if (item.age_hours === null) return t('settings.registryAutoUpdate.dueReasonUnknown');
  return t('settings.registryAutoUpdate.dueReason', {
    age: item.age_hours,
    threshold: item.stale_threshold_hours,
  });
}

function outcomeBody(
  status: RegistryAutoUpdateStatus,
  accepted: boolean,
  nextAllowedAt: string | null,
  t: ReturnType<typeof useT>,
) {
  if (status === 'manual_required')
    return t('settings.registryAutoUpdate.outcome.manualRequired.body');
  if (status === 'queued' || status === 'running') {
    return t('settings.registryAutoUpdate.outcome.running.body');
  }
  if (!accepted && nextAllowedAt) return t('settings.registryAutoUpdate.outcome.backoff.body');
  if (!accepted) return t('settings.registryAutoUpdate.outcome.rejected.body');
  return t('settings.registryAutoUpdate.outcome.accepted.body');
}

export function RegistryAutoUpdateSection({
  value,
  onChange,
}: {
  value: RegistryAutoUpdateSettings;
  onChange: (next: RegistryAutoUpdateSettings) => void;
}) {
  const t = useT();
  const toast = useToast();
  const plan = useRegistryAutoUpdateDuePlan();
  const attempt = useRequestRegistryAutoUpdate();
  const selectedProfiles = value.entity_defaults.enabled_profiles;
  const allProfiles = selectedProfiles.length === 0;

  const set = <K extends keyof RegistryAutoUpdateSettings>(
    key: K,
    next: RegistryAutoUpdateSettings[K],
  ) => onChange({ ...value, [key]: next });

  const setEntityDefaults = <K extends keyof RegistryAutoUpdateSettings['entity_defaults']>(
    key: K,
    next: RegistryAutoUpdateSettings['entity_defaults'][K],
  ) =>
    onChange({
      ...value,
      entity_defaults: { ...value.entity_defaults, [key]: next },
    });

  const setCadence = (next: RegistryAutoUpdateCadence) => set('cadence', next);
  const setCadenceKind = (kind: CadenceKind) => {
    if (kind === value.cadence.kind) return;
    if (kind === 'interval_hours') setCadence({ kind, hours: 24 });
    else if (kind === 'daily') setCadence({ kind, hour_utc: 2 });
    else setCadence({ kind, weekday: 'monday', hour_utc: 2 });
  };

  const toggleProfile = (profile: EntityKind, checked: boolean) => {
    const base = allProfiles ? [...ENTITY_KINDS] : [...selectedProfiles];
    const next = checked
      ? Array.from(new Set([...base, profile]))
      : base.filter((p) => p !== profile);
    setEntityDefaults('enabled_profiles', next.length === ENTITY_KINDS.length ? [] : next);
  };

  const runAttempt = (entityId: string) => {
    attempt.mutate(
      { id: entityId, body: { dry_run: true } },
      {
        onSuccess: (result) => {
          toast.success(
            result.accepted
              ? t('settings.registryAutoUpdate.attempt.acceptedToast')
              : t('settings.registryAutoUpdate.attempt.rejectedToast'),
          );
        },
        onError: (e) => toast.error(e),
      },
    );
  };

  const cadenceOptions = CADENCE_KINDS.map((kind) => ({
    value: kind,
    label: t(`settings.registryAutoUpdate.cadence.${kind}` as MessageKey),
  }));
  const weekdayOptions = WEEKDAYS.map((weekday) => ({
    value: weekday,
    label: t(`settings.registryAutoUpdate.weekday.${weekday}` as MessageKey),
  }));
  const cadenceFields = (() => {
    const cadence = value.cadence;
    if (cadence.kind === 'interval_hours') {
      return (
        <Field label={t('settings.registryAutoUpdate.cadence.hours')} htmlFor="registry-auto-hours">
          <Input
            id="registry-auto-hours"
            type="number"
            min={1}
            max={720}
            value={cadence.hours}
            onChange={(e) =>
              setCadence({
                kind: 'interval_hours',
                hours: numberValue(e.target.value, cadence.hours),
              })
            }
          />
        </Field>
      );
    }
    if (cadence.kind === 'daily') {
      return (
        <Field
          label={t('settings.registryAutoUpdate.cadence.hourUtc')}
          htmlFor="registry-auto-hour-utc"
        >
          <Input
            id="registry-auto-hour-utc"
            type="number"
            min={0}
            max={23}
            value={cadence.hour_utc}
            onChange={(e) =>
              setCadence({
                kind: 'daily',
                hour_utc: numberValue(e.target.value, cadence.hour_utc),
              })
            }
          />
        </Field>
      );
    }
    return (
      <>
        <Field
          label={t('settings.registryAutoUpdate.cadence.hourUtc')}
          htmlFor="registry-auto-hour-utc"
        >
          <Input
            id="registry-auto-hour-utc"
            type="number"
            min={0}
            max={23}
            value={cadence.hour_utc}
            onChange={(e) =>
              setCadence({
                ...cadence,
                hour_utc: numberValue(e.target.value, cadence.hour_utc),
              })
            }
          />
        </Field>
        <Field
          label={t('settings.registryAutoUpdate.cadence.weekday')}
          htmlFor="registry-auto-weekday"
        >
          <Select
            id="registry-auto-weekday"
            value={cadence.weekday}
            options={weekdayOptions}
            onChange={(e) =>
              setCadence({
                ...cadence,
                weekday: e.target.value as RegistryAutoUpdateWeekday,
              })
            }
          />
        </Field>
      </>
    );
  })();

  return (
    <Card
      title={t('settings.registryAutoUpdate.cardTitle')}
      actions={
        <Button
          type="button"
          variant="secondary"
          icon={<Icon.Refresh />}
          disabled={plan.isFetching}
          onClick={() => void plan.refetch()}
        >
          {plan.isFetching
            ? t('settings.registryAutoUpdate.refreshingPlan')
            : t('settings.registryAutoUpdate.refreshPlan')}
        </Button>
      }
    >
      <div className="stack">
        <div className="form settings-rows">
          <Toggle
            label={t('settings.registryAutoUpdate.enabled.label')}
            checked={value.enabled}
            onChange={(enabled) => set('enabled', enabled)}
          />
          <p className="field__hint">{t('settings.registryAutoUpdate.enabled.hint')}</p>

          <div className="registry-auto-update-grid">
            <Field
              label={t('settings.registryAutoUpdate.cadence.label')}
              htmlFor="registry-auto-cadence"
              hint={cadenceLabel(value.cadence, t)}
              help={t('settings.registryAutoUpdate.cadence.help')}
            >
              <Select
                id="registry-auto-cadence"
                value={cadenceKind(value.cadence)}
                options={cadenceOptions}
                onChange={(e) => setCadenceKind(e.target.value as CadenceKind)}
              />
            </Field>

            {cadenceFields}

            <Field
              label={t('settings.registryAutoUpdate.staleThreshold.label')}
              htmlFor="registry-auto-stale"
              hint={t('settings.registryAutoUpdate.staleThreshold.hint')}
            >
              <Input
                id="registry-auto-stale"
                type="number"
                min={1}
                max={8760}
                value={value.stale_threshold_hours}
                onChange={(e) =>
                  set(
                    'stale_threshold_hours',
                    numberValue(e.target.value, value.stale_threshold_hours),
                  )
                }
              />
            </Field>

            <Field
              label={t('settings.registryAutoUpdate.minBackoff.label')}
              htmlFor="registry-auto-min-backoff"
            >
              <Input
                id="registry-auto-min-backoff"
                type="number"
                min={1}
                max={10080}
                value={value.min_backoff_minutes}
                onChange={(e) =>
                  set('min_backoff_minutes', numberValue(e.target.value, value.min_backoff_minutes))
                }
              />
            </Field>

            <Field
              label={t('settings.registryAutoUpdate.maxBackoff.label')}
              htmlFor="registry-auto-max-backoff"
            >
              <Input
                id="registry-auto-max-backoff"
                type="number"
                min={1}
                max={10080}
                value={value.max_backoff_minutes}
                onChange={(e) =>
                  set('max_backoff_minutes', numberValue(e.target.value, value.max_backoff_minutes))
                }
              />
            </Field>

            <Field
              label={t('settings.registryAutoUpdate.maxAttempts.label')}
              htmlFor="registry-auto-max-attempts"
              hint={t('settings.registryAutoUpdate.maxAttempts.hint')}
            >
              <Input
                id="registry-auto-max-attempts"
                type="number"
                min={1}
                max={100}
                value={value.max_attempts_per_run}
                onChange={(e) =>
                  set(
                    'max_attempts_per_run',
                    numberValue(e.target.value, value.max_attempts_per_run),
                  )
                }
              />
            </Field>
          </div>

          <div className="stack--tight">
            <Toggle
              label={t('settings.registryAutoUpdate.entityDefaults.enabled')}
              checked={value.entity_defaults.enabled}
              onChange={(enabled) => setEntityDefaults('enabled', enabled)}
            />
            <p className="field__hint">{t('settings.registryAutoUpdate.entityDefaults.hint')}</p>
            <div className="registry-auto-update-profiles">
              <label className="api-key-permission">
                <input
                  type="checkbox"
                  checked={allProfiles}
                  onChange={(e) => {
                    if (e.target.checked) setEntityDefaults('enabled_profiles', []);
                  }}
                />
                {t('settings.registryAutoUpdate.entityDefaults.allProfiles')}
              </label>
              {ENTITY_KINDS.map((profile) => (
                <label key={profile} className="api-key-permission">
                  <input
                    type="checkbox"
                    checked={allProfiles || selectedProfiles.includes(profile)}
                    onChange={(e) => toggleProfile(profile, e.target.checked)}
                  />
                  {entityKindLabels[profile]}
                </label>
              ))}
            </div>
          </div>
        </div>

        <InlineWarning tone="info" title={t('settings.registryAutoUpdate.statusPanel.title')}>
          <div className="stack--tight">
            <p>{t('settings.registryAutoUpdate.statusPanel.body')}</p>
            <dl className="deflist deflist--tight">
              <div>
                <dt>{t('settings.registryAutoUpdate.outcome.disabled.title')}</dt>
                <dd>{t('settings.registryAutoUpdate.outcome.disabled.body')}</dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.outcome.manualRequired.title')}</dt>
                <dd>{t('settings.registryAutoUpdate.outcome.manualRequired.body')}</dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.outcome.backoff.title')}</dt>
                <dd>{t('settings.registryAutoUpdate.outcome.backoff.body')}</dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.outcome.running.title')}</dt>
                <dd>{t('settings.registryAutoUpdate.outcome.running.body')}</dd>
              </div>
            </dl>
          </div>
        </InlineWarning>

        {/* The plan renders as a tight deflist — generated at, mode, config, … */}
        {plan.isLoading ? (
          <SkeletonRegion
            className="stack--tight"
            label={t('settings.registryAutoUpdate.loadingPlan')}
          >
            <SkeletonDeflist rows={3} className="deflist deflist--tight" />
          </SkeletonRegion>
        ) : null}
        {plan.error ? <ErrorNote error={plan.error} /> : null}
        {plan.data ? (
          <div className="stack--tight">
            <dl className="deflist deflist--tight">
              <div>
                <dt>{t('settings.registryAutoUpdate.plan.generatedAt')}</dt>
                {/* When the plan was computed is provenance for every row below it. */}
                <dd className="mono">
                  <DateTime value={plan.data.generated_at} evidentiary />
                </dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.plan.mode')}</dt>
                <dd>
                  <Badge tone={plan.data.dry_run_only ? 'warn' : 'ok'}>
                    {plan.data.dry_run_only
                      ? t('settings.registryAutoUpdate.plan.dryRun')
                      : t('settings.registryAutoUpdate.plan.live')}
                  </Badge>
                </dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.plan.config')}</dt>
                <dd>
                  <Badge tone={plan.data.config.enabled ? 'ok' : 'neutral'}>
                    {plan.data.config.enabled
                      ? t('settings.registryAutoUpdate.plan.enabled')
                      : t('settings.registryAutoUpdate.plan.disabled')}
                  </Badge>
                </dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.plan.due')}</dt>
                <dd className="mono">{plan.data.due.length}</dd>
              </div>
            </dl>

            <dl className="deflist deflist--tight">
              <div>
                <dt>{t('settings.registryAutoUpdate.skipped.disabled')}</dt>
                <dd className="mono">{plan.data.skipped.disabled}</dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.skipped.fresh')}</dt>
                <dd className="mono">{plan.data.skipped.fresh}</dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.skipped.backoff')}</dt>
                <dd className="mono">{plan.data.skipped.backoff}</dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.skipped.running')}</dt>
                <dd className="mono">{plan.data.skipped.running}</dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.skipped.orphaned')}</dt>
                <dd className="mono">{plan.data.skipped.orphaned}</dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.skipped.capped')}</dt>
                <dd className="mono">{plan.data.skipped.capped}</dd>
              </div>
            </dl>

            {plan.data.due.length ? (
              <Table
                head={
                  <tr>
                    <th>{t('settings.registryAutoUpdate.table.entity')}</th>
                    <th>{t('settings.registryAutoUpdate.table.profile')}</th>
                    <th>{t('settings.registryAutoUpdate.table.retrieved')}</th>
                    <th>{t('settings.registryAutoUpdate.table.status')}</th>
                    <th>{t('settings.registryAutoUpdate.table.action')}</th>
                  </tr>
                }
              >
                {plan.data.due.map((item) => (
                  <tr key={item.entity_id}>
                    <td>
                      <strong>{item.entity_name}</strong>
                      <p className="field__hint mono">{item.entity_id}</p>
                    </td>
                    <td>
                      {entityKindLabels[item.entity_profile as EntityKind] ?? item.entity_profile}
                    </td>
                    <td>
                      {/* Retrieval time is the provenance of the registry snapshot being
                          judged stale, so it renders with seconds and the zone. */}
                      <DateTime className="mono" value={item.retrieved_at} evidentiary />
                      <p className="field__hint">{dueReason(item, t)}</p>
                    </td>
                    <td>
                      <Badge tone={statusTone(item.status)}>{t(statusKeys[item.status])}</Badge>
                    </td>
                    <td>
                      <Button
                        type="button"
                        variant="secondary"
                        icon={<Icon.Refresh />}
                        disabled={attempt.isPending}
                        onClick={() => runAttempt(item.entity_id)}
                      >
                        {attempt.isPending
                          ? t('settings.registryAutoUpdate.attempt.pending')
                          : t('settings.registryAutoUpdate.attempt.button')}
                      </Button>
                    </td>
                  </tr>
                ))}
              </Table>
            ) : (
              <EmptyState title={t('settings.registryAutoUpdate.empty.title')}>
                <p>{t('settings.registryAutoUpdate.empty.body')}</p>
              </EmptyState>
            )}
          </div>
        ) : null}

        {attempt.data ? (
          <InlineWarning
            tone={attempt.data.accepted ? 'info' : 'warn'}
            title={t('settings.registryAutoUpdate.attempt.resultTitle')}
          >
            <dl className="deflist deflist--tight">
              <div>
                <dt>{t('settings.registryAutoUpdate.table.status')}</dt>
                <dd>
                  <Badge tone={statusTone(attempt.data.status)}>
                    {t(statusKeys[attempt.data.status])}
                  </Badge>
                </dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.attempt.accepted')}</dt>
                <dd>
                  {attempt.data.accepted
                    ? t('settings.registryAutoUpdate.yes')
                    : t('settings.registryAutoUpdate.no')}
                </dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.attempt.nextAllowed')}</dt>
                <dd className="mono">
                  <DateTime value={attempt.data.next_allowed_at} />
                </dd>
              </div>
              <div>
                <dt>{t('settings.registryAutoUpdate.attempt.failures')}</dt>
                <dd className="mono">{attempt.data.failure_count}</dd>
              </div>
            </dl>
            <p>
              {outcomeBody(
                attempt.data.status,
                attempt.data.accepted,
                attempt.data.next_allowed_at,
                t,
              )}
            </p>
          </InlineWarning>
        ) : null}
      </div>
    </Card>
  );
}
