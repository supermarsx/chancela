/**
 * The API sub-tab's "Servidor" pane (t82b) — everything that configures the API server itself.
 *
 * The API surface was scattered the same way MCP was: a service row inside the generic platform
 * service list, a log-area level and a service override inside the generic logging grid, and a
 * whole security posture (`CHANCELA_CORS_ALLOWED_ORIGINS`, the rate limiter, HSTS, the session
 * lifetime cap) that is read from the process environment at startup and was surfaced nowhere in
 * the product at all.
 *
 * **Why the API keys live in a sibling pane rather than in this one.** They belong to the API
 * surface and the user asked to aggregate it, so they share the tab — but they must NOT share the
 * panel. Key management is gated on `user.manage` and manages its own data, while everything here
 * is `settings.manage` working-copy state under the page's disabled fieldset. Folding the keys
 * table into this panel would put it inside that fieldset and thereby take API-key management away
 * from a `user.manage` holder who lacks `settings.manage` — a silent narrowing of who may rotate a
 * credential. The tab therefore splits: `.../operations/api` is this pane and
 * `.../operations/chaves-api` is the keys
 * pane, both under one "API" button. The keys address is unchanged, so its bookmarks and its
 * standalone (no-savebar, no-fieldset) treatment survive byte-for-byte.
 *
 * **What is NOT here.** `connectors.allowed_hosts` is *outbound* connector egress, not the inbound
 * API surface — `chancela-api` reads it only to hand to `chancela-connectors`. It stays in
 * Plataforma and is cross-referenced below with that distinction spelled out, because "is this the
 * API's allow-list?" is exactly the question an operator will arrive with. The platform log tail
 * spans app/api/mcp_stdio and stays in Plataforma too.
 */
import { usePlatformServices } from '../../api/hooks';
import type { PlatformLogLevel, PlatformSettings } from '../../api/types';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import {
  Badge,
  ButtonLink,
  Card,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  InlineWarning,
  Select,
  Skeleton,
  SkeletonRegion,
  Table,
  useToast,
} from '../../ui';
import {
  API_SERVICE_ID,
  LOGS_TAB_PATH,
  SERVICES_TAB_PATH,
  ServiceRow,
  effectiveLogLevel,
  logLevelOptions,
  loggingSourceText,
  overrideOptions,
} from './PlatformOperationsSection';

/**
 * The launch-time environment surface, transcribed from `chancela-server/src/main.rs`,
 * `chancela-api/src/cors.rs` and the wp25-sec block in `chancela-api/src/lib.rs`. READ-ONLY: these
 * are resolved once when the process starts and no endpoint can write them, so they are shown as a
 * table of facts rather than dressed up as editable settings.
 *
 * Defaults are the ones the running server actually uses — note `CHANCELA_RATE_LIMIT_ENABLED`
 * defaults ON for the server binary even though the embeddable `RateLimitConfig::default()` is off.
 */
const API_ENV_ROWS: readonly { name: string; meaning: MessageKey; fallback: string }[] = [
  { name: 'CHANCELA_ADDR', meaning: 'settings.api.env.addr', fallback: '127.0.0.1:8080' },
  { name: 'CHANCELA_CORS_ALLOWED_ORIGINS', meaning: 'settings.api.env.cors', fallback: '—' },
  { name: 'CHANCELA_RATE_LIMIT_ENABLED', meaning: 'settings.api.env.rateLimit', fallback: 'true' },
  {
    name: 'CHANCELA_RATE_LIMIT_PER_SECOND',
    meaning: 'settings.api.env.ratePerSecond',
    fallback: '50',
  },
  { name: 'CHANCELA_RATE_LIMIT_BURST', meaning: 'settings.api.env.rateBurst', fallback: '100' },
  {
    name: 'CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR',
    meaning: 'settings.api.env.trustForwarded',
    fallback: 'false',
  },
  { name: 'CHANCELA_HSTS_MAX_AGE', meaning: 'settings.api.env.hstsMaxAge', fallback: '63072000' },
  {
    name: 'CHANCELA_HSTS_INCLUDE_SUBDOMAINS',
    meaning: 'settings.api.env.hstsSubdomains',
    fallback: 'true',
  },
  { name: 'CHANCELA_HSTS_PRELOAD', meaning: 'settings.api.env.hstsPreload', fallback: 'false' },
  {
    name: 'CHANCELA_SESSION_MAX_LIFETIME',
    meaning: 'settings.api.env.sessionLifetime',
    fallback: '604800',
  },
];

export function ApiServerSection({
  value,
  canManage,
  onChange,
}: {
  value: PlatformSettings;
  canManage: boolean;
  onChange: (value: PlatformSettings) => void;
}) {
  const t = useT();
  const toast = useToast();
  const services = usePlatformServices();
  const api = services.data?.services.find((service) => service.id === API_SERVICE_ID);

  const setLevel = (level: PlatformLogLevel) =>
    onChange({ ...value, logging: { ...value.logging, api: level } });
  const setOverride = (level: PlatformLogLevel | '') => {
    const service_overrides = { ...value.logging.service_overrides };
    if (level === '') delete service_overrides[API_SERVICE_ID];
    else service_overrides[API_SERVICE_ID] = level;
    onChange({ ...value, logging: { ...value.logging, service_overrides } });
  };

  const effective = effectiveLogLevel(value.logging, API_SERVICE_ID);

  return (
    <div className="stack">
      <Card title={t('settings.api.cardTitle')}>
        <div className="form settings-rows">
          <p className="field__hint">{t('settings.api.intro')}</p>
          {services.isLoading ? (
            <SkeletonRegion
              className="platform-service-list"
              label={t('settings.platform.loading')}
            >
              <Skeleton height="3.2rem" />
            </SkeletonRegion>
          ) : null}
          {services.error ? <ErrorNote error={services.error} /> : null}
          {services.data && !api ? (
            <InlineWarning tone="info" title={t('settings.platform.empty.title')}>
              {t('settings.platform.empty.body')}
            </InlineWarning>
          ) : null}
          {api ? (
            <div className="platform-service-list">
              <ServiceRow
                service={api}
                canManage={canManage}
                onControlError={(error) => toast.error(error)}
              />
            </div>
          ) : null}
        </div>
      </Card>

      <Card title={t('settings.api.logging.title')}>
        <div className="form settings-rows">
          <p className="field__hint">{t('settings.api.logging.hint')}</p>
          <Field
            label={t('settings.platform.logging.api')}
            htmlFor="platform-log-api"
            help={t('settings.platform.help.logLevels')}
          >
            <Select
              id="platform-log-api"
              value={value.logging.api}
              options={logLevelOptions(t)}
              onChange={(e) => setLevel(e.target.value as PlatformLogLevel)}
            />
          </Field>
          <Field
            label={t('settings.platform.logging.override.api')}
            htmlFor="platform-log-override-api"
            help={t('settings.platform.help.overrides')}
          >
            <Select
              id="platform-log-override-api"
              value={value.logging.service_overrides[API_SERVICE_ID] ?? ''}
              options={overrideOptions(t)}
              onChange={(e) => setOverride(e.target.value as PlatformLogLevel | '')}
            />
          </Field>
          <div
            className="platform-logging-effective"
            role="group"
            aria-label={t('settings.platform.effectiveLog')}
          >
            <p className="card__label">
              {t('settings.platform.effectiveLog')}{' '}
              <FieldHelp text={t('settings.platform.help.effective')} />
            </p>
            <div className="platform-logging-effective__item">
              <Badge tone={effective === 'off' ? 'neutral' : 'accent'}>
                {t(`settings.platform.logLevel.${effective}` as MessageKey)}
              </Badge>
              <span className="field__hint">
                {loggingSourceText(value.logging, API_SERVICE_ID, t)}
              </span>
            </div>
          </div>
        </div>
      </Card>

      <Card title={t('settings.env.title')}>
        <p className="muted">{t('settings.api.env.hint')}</p>
        <InlineWarning tone="info" title={t('settings.api.tls.title')}>
          {t('settings.api.tls.body')}
        </InlineWarning>
        <Table
          caption={t('settings.env.title')}
          head={
            <tr>
              <th scope="col">{t('settings.env.col.variable')}</th>
              <th scope="col">{t('settings.env.col.meaning')}</th>
              <th scope="col">{t('settings.env.col.default')}</th>
            </tr>
          }
        >
          {API_ENV_ROWS.map((row) => (
            <tr key={row.name}>
              <td className="mono">{row.name}</td>
              <td>{t(row.meaning)}</td>
              <td className="mono">{row.fallback}</td>
            </tr>
          ))}
        </Table>
      </Card>

      {/* Cross-references, not relocations. Each of these governs something wider than the API
          server, so each keeps its existing single writer and its existing home. */}
      <Card title={t('settings.api.related.title')}>
        <dl className="deflist deflist--tight">
          <div>
            <dt>{t('settings.connectorEgress.title')}</dt>
            <dd>{t('settings.api.related.egress')}</dd>
          </div>
          <div>
            <dt>{t('settings.platform.logs.cardTitle')}</dt>
            <dd>{t('settings.api.related.logTail')}</dd>
          </div>
        </dl>
        <div className="row-wrap">
          <ButtonLink to={SERVICES_TAB_PATH} icon={<Icon.Power />}>
            {t('settings.platform.tab.services')}
          </ButtonLink>
          <ButtonLink to={LOGS_TAB_PATH} icon={<Icon.Layers />}>
            {t('settings.platform.tab.logs')}
          </ButtonLink>
        </div>
      </Card>
    </div>
  );
}
