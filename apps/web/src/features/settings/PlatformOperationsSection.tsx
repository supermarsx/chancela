import { useMemo, useState, type ReactNode } from 'react';
import { useControlPlatformService, usePlatformServices } from '../../api/hooks';
import {
  PLATFORM_LOG_LEVELS,
  PLATFORM_SERVICE_IDS,
  type PlatformActionCapability,
  type PlatformAuditEvent,
  type PlatformControlOutcomeKind,
  type PlatformLogLevel,
  type PlatformLoggingSettings,
  type PlatformServiceAction,
  type PlatformServiceDesiredState,
  type PlatformServiceId,
  type PlatformServiceStatus,
  type PlatformSettings,
  type PlatformRuntimeStatus,
} from '../../api/types';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  InlineWarning,
  Loading,
  Select,
  SubNav,
  useToast,
} from '../../ui';

/** The Operations surface splits into two logically-grouped sub-sub-tabs, each reached
 *  through the shared `<SubNav>` (the same segmented idiom the parent settings page uses):
 *  "Serviços" holds the desired-state service controls + operations audit; "Registos"
 *  holds the log-level configuration and the structured API log tail/viewer. */
type OperationsTab = 'servicos' | 'registos';

const LOG_BASE_FIELDS = ['global', 'app', 'api', 'mcp'] as const;
const LOG_OVERRIDE_IDS: readonly PlatformServiceId[] = ['app', 'api', 'mcp_stdio'];
const LOG_LEVEL_RANK: Record<PlatformLogLevel, number> = {
  trace: 0,
  debug: 1,
  info: 2,
  warn: 3,
  error: 4,
  off: 5,
};
const AI_MCP_ASSURANCE_KEYS = [
  'settings.platform.assurance.gates',
  'settings.platform.assurance.rbac',
  'settings.platform.assurance.drafts',
  'settings.platform.assurance.signature',
] as const satisfies readonly MessageKey[];

function logLevelOptions(t: ReturnType<typeof useT>) {
  return PLATFORM_LOG_LEVELS.map((level) => ({
    value: level,
    label: t(`settings.platform.logLevel.${level}` as MessageKey),
  }));
}

function overrideOptions(t: ReturnType<typeof useT>) {
  return [
    { value: '', label: t('settings.platform.logging.override.none') },
    ...logLevelOptions(t),
  ];
}

function statusTone(value: PlatformRuntimeStatus | PlatformServiceDesiredState) {
  return value === 'running' ? 'ok' : value === 'unknown' ? 'warn' : 'neutral';
}

function booleanTone(value: boolean) {
  return value ? 'ok' : 'neutral';
}

function outcomeTone(outcome: PlatformControlOutcomeKind) {
  if (outcome === 'restart_required') return 'warn';
  if (outcome === 'supervisor_required') return 'accent';
  return 'neutral';
}

function desiredStateForAction(action: PlatformServiceAction): PlatformServiceDesiredState {
  return action === 'stop' ? 'stopped' : 'running';
}

function isMeaningfulDesiredStateAction(
  service: PlatformServiceStatus,
  capability: PlatformActionCapability,
) {
  if (capability.action === 'restart') return service.desired_state === 'running';
  return service.desired_state !== desiredStateForAction(capability.action);
}

function logAreaField(
  serviceId: PlatformServiceId,
): Exclude<(typeof LOG_BASE_FIELDS)[number], 'global'> {
  if (serviceId === 'mcp_stdio') return 'mcp';
  return serviceId;
}

function stricterLogLevel(left: PlatformLogLevel, right: PlatformLogLevel): PlatformLogLevel {
  return LOG_LEVEL_RANK[left] >= LOG_LEVEL_RANK[right] ? left : right;
}

function effectiveLogLevel(
  logging: PlatformLoggingSettings,
  serviceId: PlatformServiceId,
): PlatformLogLevel {
  if (logging.global === 'off') return 'off';
  const override = logging.service_overrides[serviceId];
  if (override) return override;
  return stricterLogLevel(logging.global, logging[logAreaField(serviceId)]);
}

function loggingSourceText(
  logging: PlatformLoggingSettings,
  serviceId: PlatformServiceId,
  t: ReturnType<typeof useT>,
) {
  if (logging.global === 'off') {
    return `${t('settings.platform.logging.global')}: ${t('settings.platform.logLevel.off')}`;
  }
  const override = logging.service_overrides[serviceId];
  if (override) {
    return `${t('settings.platform.logging.overrides')}: ${t(
      `settings.platform.logLevel.${override}` as MessageKey,
    )}`;
  }
  const area = logAreaField(serviceId);
  return `${t('settings.platform.logging.global')}: ${t(
    `settings.platform.logLevel.${logging.global}` as MessageKey,
  )} · ${t(`settings.platform.logging.${area}` as MessageKey)}: ${t(
    `settings.platform.logLevel.${logging[area]}` as MessageKey,
  )}`;
}

function actionIcon(action: PlatformServiceAction) {
  if (action === 'restart') return <Icon.Refresh />;
  if (action === 'stop') return <Icon.Close />;
  return <Icon.Power />;
}

function serviceFallbackLabel(id: PlatformServiceId, t: ReturnType<typeof useT>) {
  if (id === 'api') return t('settings.platform.service.api');
  if (id === 'mcp_stdio') return t('settings.platform.service.mcp_stdio');
  return t('settings.platform.service.app');
}

function ServiceBadges({ service }: { service: PlatformServiceStatus }) {
  const t = useT();
  return (
    <div className="row-wrap">
      <Badge tone={booleanTone(service.configured)}>
        {service.configured
          ? t('settings.platform.configured.yes')
          : t('settings.platform.configured.no')}
      </Badge>
      <Badge tone={booleanTone(service.enabled)}>
        {service.enabled ? t('settings.platform.enabled.yes') : t('settings.platform.enabled.no')}
      </Badge>
      <Badge tone={statusTone(service.desired_state)}>
        {t(`settings.platform.desired.${service.desired_state}` as MessageKey)}
      </Badge>
      <Badge tone={statusTone(service.actual_runtime_status)}>
        {t(`settings.platform.runtime.${service.actual_runtime_status}` as MessageKey)}
      </Badge>
    </div>
  );
}

function AiMcpAssurancePanel() {
  const t = useT();
  return (
    <InlineWarning tone="info" title={t('settings.platform.assurance.title')}>
      <ul>
        {AI_MCP_ASSURANCE_KEYS.map((key) => (
          <li key={key}>{t(key)}</li>
        ))}
      </ul>
    </InlineWarning>
  );
}

function LastAction({ service }: { service: PlatformServiceStatus }) {
  const t = useT();
  const last = service.last_action;
  if (!last) {
    return <p className="field__hint">{t('settings.platform.lastAction.empty')}</p>;
  }
  return (
    <dl className="deflist deflist--tight platform-action-summary">
      <div>
        <dt>{t('settings.platform.action')}</dt>
        <dd>{t(`settings.platform.action.${last.action}` as MessageKey)}</dd>
      </div>
      <div>
        <dt>{t('settings.platform.outcome')}</dt>
        <dd>
          <Badge tone={outcomeTone(last.outcome)}>
            {t(`settings.platform.outcome.${last.outcome}` as MessageKey)}
          </Badge>
        </dd>
      </div>
      <div>
        <dt>{t('settings.platform.requestedBy')}</dt>
        <dd className="mono">{last.requested_by}</dd>
      </div>
      <div>
        <dt>{t('settings.platform.requestedAt')}</dt>
        <dd className="mono">{last.requested_at}</dd>
      </div>
      <div className="platform-action-summary__message">
        <dt>{t('settings.platform.message')}</dt>
        <dd>{last.message}</dd>
      </div>
    </dl>
  );
}

function ActionCapabilities({ service }: { service: PlatformServiceStatus }) {
  const t = useT();
  if (service.controllable_actions.length === 0) return null;
  return (
    <div className="platform-control-support">
      <p className="card__label">
        {t('settings.platform.action')} <FieldHelp text={t('settings.platform.help.outcomes')} />
      </p>
      <ul>
        {service.controllable_actions.map((capability) => (
          <li key={capability.action}>
            <div className="platform-control-support__head">
              <span>{t(`settings.platform.action.${capability.action}` as MessageKey)}</span>
              <Badge tone={outcomeTone(capability.outcome)}>
                {t(`settings.platform.outcome.${capability.outcome}` as MessageKey)}
              </Badge>
            </div>
            <p>{capability.limitation}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ServiceRow({
  service,
  canManage,
  onControlError,
}: {
  service: PlatformServiceStatus;
  canManage: boolean;
  onControlError: (error: unknown) => void;
}) {
  const t = useT();
  const toast = useToast();
  const control = useControlPlatformService();
  const meaningfulActions = service.controllable_actions.filter((capability) =>
    isMeaningfulDesiredStateAction(service, capability),
  );

  const recordAction = (action: PlatformServiceAction) => {
    control.mutate(
      { id: service.id, action },
      {
        onSuccess: (response) => toast.success(response.result.message),
        onError: onControlError,
      },
    );
  };

  return (
    <section className="platform-service-row">
      <div className="platform-service-row__main">
        <div className="platform-service-row__head">
          <div>
            <p className="card__label">{serviceFallbackLabel(service.id, t)}</p>
            <h4 className="platform-service-row__title">{service.label}</h4>
          </div>
          <ServiceBadges service={service} />
        </div>

        <dl className="deflist deflist--tight">
          <div>
            <dt>{t('settings.platform.configured')}</dt>
            <dd>
              {service.configured
                ? t('settings.platform.configured.yes')
                : t('settings.platform.configured.no')}
            </dd>
          </div>
          <div>
            <dt>{t('settings.platform.enabled')}</dt>
            <dd>
              {service.enabled
                ? t('settings.platform.enabled.yes')
                : t('settings.platform.enabled.no')}
            </dd>
          </div>
          <div>
            <dt>{t('settings.platform.desired')}</dt>
            <dd>{t(`settings.platform.desired.${service.desired_state}` as MessageKey)}</dd>
          </div>
          <div>
            <dt>{t('settings.platform.runtime')}</dt>
            <dd>{t(`settings.platform.runtime.${service.actual_runtime_status}` as MessageKey)}</dd>
          </div>
          <div>
            <dt>{t('settings.platform.effectiveLog')}</dt>
            <dd>{t(`settings.platform.logLevel.${service.logging_level}` as MessageKey)}</dd>
          </div>
        </dl>

        {meaningfulActions.length > 0 ? (
          <div className="platform-action-row">
            {meaningfulActions.map((capability) => {
              const action = capability.action;
              const pending =
                control.isPending &&
                control.variables?.id === service.id &&
                control.variables?.action === action;
              return (
                <Button
                  key={action}
                  type="button"
                  variant={action === 'restart' ? 'secondary' : 'ghost'}
                  icon={actionIcon(action)}
                  disabled={!canManage || pending}
                  onClick={() => recordAction(action)}
                >
                  {pending
                    ? t('settings.platform.action.recording')
                    : t(`settings.platform.action.record.${action}` as MessageKey)}
                  <span className="platform-action-row__outcome">
                    {t(`settings.platform.outcome.${capability.outcome}` as MessageKey)}
                  </span>
                </Button>
              );
            })}
          </div>
        ) : null}

        {/* Progressive disclosure: the dense per-service control matrix and backend
            limitations are collapsed by default so the row leads with status + the
            meaningful actions, and the honest-limitation evidence stays one click away. */}
        <details className="platform-service-row__details">
          <summary>{t('settings.platform.serviceDetails')}</summary>
          <div className="stack--tight">
            <ActionCapabilities service={service} />
            <div className="platform-limitations">
              <p className="card__label">{t('settings.platform.limitations')}</p>
              <ul>
                {service.limitations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        </details>
      </div>

      <aside className="platform-service-row__aside">
        <p className="card__label">{t('settings.platform.lastAction')}</p>
        <LastAction service={service} />
      </aside>
    </section>
  );
}

function LoggingEffectiveSummary({ logging }: { logging: PlatformLoggingSettings }) {
  const t = useT();
  return (
    <div
      className="platform-logging-effective"
      role="group"
      aria-label={t('settings.platform.effectiveLog')}
    >
      <p className="card__label">
        {t('settings.platform.effectiveLog')}{' '}
        <FieldHelp text={t('settings.platform.help.effective')} />
      </p>
      <div className="platform-logging-effective__grid">
        {PLATFORM_SERVICE_IDS.map((serviceId) => {
          const effective = effectiveLogLevel(logging, serviceId);
          return (
            <div key={serviceId} className="platform-logging-effective__item">
              <span>{serviceFallbackLabel(serviceId, t)}</span>
              <Badge tone={effective === 'off' ? 'neutral' : 'accent'}>
                {t(`settings.platform.logLevel.${effective}` as MessageKey)}
              </Badge>
              <span className="field__hint">{loggingSourceText(logging, serviceId, t)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AuditTail({ audit }: { audit: PlatformAuditEvent[] }) {
  const t = useT();
  const tail = audit.slice(-5).reverse();
  return (
    <Card title={t('settings.platform.auditTail')}>
      {tail.length === 0 ? (
        <p className="field__hint">{t('settings.platform.audit.empty')}</p>
      ) : (
        <ol className="platform-audit-list">
          {tail.map((event) => (
            <li key={`${event.service_id}:${event.requested_at}:${event.action}`}>
              <div className="platform-audit-list__head">
                <span className="mono">{event.requested_at}</span>
                <Badge tone={outcomeTone(event.outcome)}>
                  {t(`settings.platform.outcome.${event.outcome}` as MessageKey)}
                </Badge>
              </div>
              <p>
                <strong>{serviceFallbackLabel(event.service_id, t)}</strong>{' '}
                {t(`settings.platform.action.${event.action}` as MessageKey)} ·{' '}
                {t(`settings.platform.desired.${event.desired_state}` as MessageKey)}
              </p>
              <p className="field__hint">
                {event.requested_by}: {event.message}
              </p>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

export function PlatformOperationsSection({
  value,
  audit,
  canManage,
  onChange,
  logsPanel,
}: {
  value: PlatformSettings;
  audit: PlatformAuditEvent[];
  canManage: boolean;
  onChange: (value: PlatformSettings) => void;
  /** The structured API log tail/viewer, hosted by the settings page and rendered inside
   *  the "Registos" sub-sub-tab so the log-level config and the log evidence sit together. */
  logsPanel?: ReactNode;
}) {
  const t = useT();
  const toast = useToast();
  const services = usePlatformServices();
  const levels = useMemo(() => logLevelOptions(t), [t]);
  const overrides = useMemo(() => overrideOptions(t), [t]);
  const [tab, setTab] = useState<OperationsTab>('servicos');

  const setLogging = (logging: PlatformLoggingSettings) => onChange({ ...value, logging });
  const setBaseLevel = (field: (typeof LOG_BASE_FIELDS)[number], level: PlatformLogLevel) =>
    setLogging({ ...value.logging, [field]: level });
  const setOverride = (serviceId: PlatformServiceId, level: PlatformLogLevel | '') => {
    const service_overrides = { ...value.logging.service_overrides };
    if (level === '') delete service_overrides[serviceId];
    else service_overrides[serviceId] = level;
    setLogging({ ...value.logging, service_overrides });
  };

  const tabDescription =
    tab === 'servicos'
      ? t('settings.platform.tab.services.desc')
      : t('settings.platform.tab.logs.desc');

  return (
    <div className="stack">
      <SubNav
        items={[
          {
            id: 'servicos',
            label: t('settings.platform.tab.services'),
            icon: <Icon.Power />,
          },
          {
            id: 'registos',
            label: t('settings.platform.tab.logs'),
            icon: <Icon.Layers />,
          },
        ]}
        active={tab}
        onSelect={setTab}
        ariaLabel={t('settings.platform.subnav.aria')}
      />
      <p className="field__hint">{tabDescription}</p>

      <div className="route-transition stack" key={tab}>
        {tab === 'servicos' ? (
          <>
            <Card title={t('settings.platform.cardTitle')}>
              <div className="form">
                <p className="field__hint">
                  {t('settings.platform.intro')}{' '}
                  <FieldHelp text={t('settings.platform.help.services')} />
                </p>
                <AiMcpAssurancePanel />
                {services.isLoading ? <Loading label={t('settings.platform.loading')} /> : null}
                {services.error ? <ErrorNote error={services.error} /> : null}
                {services.data && services.data.services.length === 0 ? (
                  <InlineWarning tone="info" title={t('settings.platform.empty.title')}>
                    {t('settings.platform.empty.body')}
                  </InlineWarning>
                ) : null}
                {services.data ? (
                  <div className="platform-service-list">
                    {services.data.services.map((service) => (
                      <ServiceRow
                        key={service.id}
                        service={service}
                        canManage={canManage}
                        onControlError={(error) => toast.error(error)}
                      />
                    ))}
                  </div>
                ) : null}
              </div>
            </Card>

            <AuditTail audit={audit} />
          </>
        ) : (
          <>
            <Card title={t('settings.platform.logging.cardTitle')}>
              <div className="form">
                <p className="field__hint">{t('settings.platform.logging.hint')}</p>
                <div className="platform-logging-grid">
                  {LOG_BASE_FIELDS.map((field) => (
                    <Field
                      key={field}
                      label={t(`settings.platform.logging.${field}` as MessageKey)}
                      htmlFor={`platform-log-${field}`}
                      help={field === 'global' ? t('settings.platform.help.logLevels') : undefined}
                    >
                      <Select
                        id={`platform-log-${field}`}
                        value={value.logging[field]}
                        options={levels}
                        onChange={(e) => setBaseLevel(field, e.target.value as PlatformLogLevel)}
                      />
                    </Field>
                  ))}
                </div>
                <LoggingEffectiveSummary logging={value.logging} />
                <div className="stack--tight">
                  <p className="card__label">
                    {t('settings.platform.logging.overrides')}{' '}
                    <FieldHelp text={t('settings.platform.help.overrides')} />
                  </p>
                  <p className="field__hint">{t('settings.platform.logging.overridesHint')}</p>
                  <div className="platform-logging-grid">
                    {LOG_OVERRIDE_IDS.map((serviceId) => (
                      <Field
                        key={serviceId}
                        label={t(`settings.platform.logging.override.${serviceId}` as MessageKey)}
                        htmlFor={`platform-log-override-${serviceId}`}
                      >
                        <Select
                          id={`platform-log-override-${serviceId}`}
                          value={value.logging.service_overrides[serviceId] ?? ''}
                          options={overrides}
                          onChange={(e) =>
                            setOverride(serviceId, e.target.value as PlatformLogLevel | '')
                          }
                        />
                      </Field>
                    ))}
                  </div>
                </div>
              </div>
            </Card>

            {logsPanel}
          </>
        )}
      </div>
    </div>
  );
}
