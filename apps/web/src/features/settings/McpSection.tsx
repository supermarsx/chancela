/**
 * The MCP sub-tab (t82) — one address for every MCP-specific control.
 *
 * Chancela ships an MCP stdio server, and its configuration had accumulated in four unrelated
 * places: a service row inside the generic platform service list, a log-area level and a service
 * override inside the generic logging grid, an assurance note bolted onto the services card, and a
 * set of `CHANCELA_MCP_*` process-environment variables documented nowhere in the product. This
 * tab gathers them.
 *
 * **What deliberately did NOT move, and why.** Two neighbours look like MCP configuration and are
 * not:
 *
 * - `connectors.allowed_hosts` (`CHANCELA_CONNECTOR_ALLOWED_HOSTS`) is the connector **egress
 *   allow-list**. `chancela-mcp` never reads it — grep the crate — and it governs connector
 *   uploads, a different subject with a different blast radius. Moving a security control under a
 *   heading that misnames it would be worse than leaving it where it is, so it stays in Plataforma
 *   and is not even cross-referenced here: naming it on this tab would itself assert the wrong
 *   grouping.
 * - API keys authenticate every integration client, not only MCP. Cross-referenced, not moved.
 *
 * **`ai.enabled` now lives here, and only here.** It was left in Gestão on the reasoning that it
 * gates the AI features as well as MCP, and one writer per setting is what stops two screens
 * disagreeing. The user overruled the placement, not the principle: the writer moved rather than
 * being duplicated, Gestão keeps a read-only pointer to it, and the tab is labelled "IA e MCP" so
 * the strip says what it actually governs.
 *
 * Everything the tab writes goes to the same endpoints, fields and permission gate it wrote
 * before: the service row posts `/v1/platform/services/mcp_stdio/actions/{action}` behind
 * `canManage` (`settings.manage`); the two log selects and the AI toggle edit the shared settings
 * working copy inside the page's `settings.manage` fieldset, and the toggle keeps Gestão's
 * hidden-not-disabled treatment for anyone without that permission.
 */
import { usePlatformServices } from '../../api/hooks';
import type { PlatformLogLevel, PlatformSettings } from '../../api/types';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import {
  ButtonLink,
  Card,
  ErrorNote,
  Icon,
  InlineWarning,
  Skeleton,
  SkeletonRegion,
  Table,
  Toggle,
  useToast,
} from '../../ui';
import { AiMcpAssurancePanel, MCP_SERVICE_ID, ServiceRow } from './PlatformOperationsSection';
import {
  effectiveLogLevel,
  loggingSourceText,
  PlatformLoggingTable,
  type PlatformLoggingTableRow,
} from './PlatformLoggingTable';

/**
 * The launch-time environment surface, transcribed from `McpConfig::from_env` in
 * `crates/chancela-mcp/src/config.rs`. It is READ-ONLY on purpose: these are read from the
 * process environment when the stdio server launches, and there is no API that can write them.
 * Showing them as a table of facts is honest; dressing them as editable settings would not be.
 * The API key is listed by name only — its value is never carried to this client.
 */
const MCP_ENV_ROWS: readonly { name: string; meaning: MessageKey; fallback: string }[] = [
  { name: 'CHANCELA_MCP_ENABLED', meaning: 'settings.mcp.env.enabled', fallback: 'false' },
  { name: 'CHANCELA_AI_ENABLED', meaning: 'settings.mcp.env.aiGate', fallback: 'false' },
  { name: 'CHANCELA_MCP_TRANSPORT', meaning: 'settings.mcp.env.transport', fallback: 'stdio' },
  {
    name: 'CHANCELA_MCP_BASE_URL',
    meaning: 'settings.mcp.env.baseUrl',
    fallback: 'http://127.0.0.1:8080',
  },
  { name: 'CHANCELA_MCP_BASE_PATH', meaning: 'settings.mcp.env.basePath', fallback: '/api/v1' },
  { name: 'CHANCELA_MCP_API_KEY', meaning: 'settings.mcp.env.apiKey', fallback: '—' },
  { name: 'CHANCELA_MCP_ENABLED_TOOLS', meaning: 'settings.mcp.env.tools', fallback: 'all' },
  { name: 'CHANCELA_MCP_BIND', meaning: 'settings.mcp.env.bind', fallback: '—' },
];

export function McpSection({
  value,
  aiEnabled,
  canManage,
  onChange,
  onAiEnabledChange,
}: {
  value: PlatformSettings;
  /** `settings.ai.enabled`. This section is its only writer. */
  aiEnabled: boolean;
  canManage: boolean;
  onChange: (value: PlatformSettings) => void;
  onAiEnabledChange: (enabled: boolean) => void;
}) {
  const t = useT();
  const toast = useToast();
  const services = usePlatformServices();
  const mcp = services.data?.services.find((service) => service.id === MCP_SERVICE_ID);

  const setLevel = (level: PlatformLogLevel) =>
    onChange({ ...value, logging: { ...value.logging, mcp: level } });
  const setOverride = (level: PlatformLogLevel | '') => {
    const service_overrides = { ...value.logging.service_overrides };
    if (level === '') delete service_overrides[MCP_SERVICE_ID];
    else service_overrides[MCP_SERVICE_ID] = level;
    onChange({ ...value, logging: { ...value.logging, service_overrides } });
  };
  const effective = effectiveLogLevel(value.logging, MCP_SERVICE_ID);
  const loggingRows: PlatformLoggingTableRow[] = [
    {
      id: 'mcp_stdio',
      scope: t('settings.platform.service.mcp_stdio'),
      area: {
        id: 'platform-log-mcp',
        label: t('settings.platform.logging.mcp'),
        value: value.logging.mcp,
        onChange: setLevel,
      },
      override: {
        id: 'platform-log-override-mcp_stdio',
        label: t('settings.platform.logging.override.mcp_stdio'),
        value: value.logging.service_overrides[MCP_SERVICE_ID] ?? '',
        onChange: setOverride,
      },
      effective,
      source: loggingSourceText(value.logging, MCP_SERVICE_ID, t),
      configuration: t('settings.mcp.cardTitle'),
    },
  ];

  return (
    <div className="stack">
      {/* The tenant AI/MCP gate. It lived in Gestão until the user ruled that it belongs here and
          only here, so this is now its ONE writer — Gestão keeps a read-only pointer.
          `canManage` reproduces Gestão's gating exactly: the toggle was HIDDEN there from anyone
          without `settings.manage`, not merely disabled, so it is hidden here on the same
          condition. It also sits inside the settings page's `settings.manage` fieldset, and it
          writes `ai.enabled` on the same whole-document `PUT /v1/settings` autosave as before. */}
      {canManage ? (
        <Card title={t('settings.mcp.gate.title')}>
          <div className="form settings-rows">
            <Toggle
              label={t('settings.management.ai.label')}
              checked={aiEnabled}
              onChange={onAiEnabledChange}
            />
            <p className="field__hint">{t('settings.management.ai.hint')}</p>
          </div>
        </Card>
      ) : null}

      <Card title={t('settings.mcp.cardTitle')}>
        <div className="form settings-rows">
          <p className="field__hint">{t('settings.mcp.intro')}</p>
          <AiMcpAssurancePanel />
          {/* Same placeholder idiom as the platform service list it came from: the row that
              arrives, on the container it arrives in. */}
          {services.isLoading ? (
            <SkeletonRegion
              className="platform-service-list"
              label={t('settings.platform.loading')}
            >
              <Skeleton height="3.2rem" />
            </SkeletonRegion>
          ) : null}
          {services.error ? <ErrorNote error={services.error} /> : null}
          {services.data && !mcp ? (
            <InlineWarning tone="info" title={t('settings.platform.empty.title')}>
              {t('settings.platform.empty.body')}
            </InlineWarning>
          ) : null}
          {mcp ? (
            <div className="platform-service-list">
              <ServiceRow
                service={mcp}
                canManage={canManage}
                onControlError={(error) => toast.error(error)}
              />
            </div>
          ) : null}
        </div>
      </Card>

      <Card title={t('settings.mcp.logging.title')}>
        <div className="form settings-rows">
          <p className="field__hint">{t('settings.mcp.logging.hint')}</p>
          <PlatformLoggingTable caption={t('settings.mcp.logging.title')} rows={loggingRows} />
        </div>
      </Card>

      <Card title={t('settings.env.title')}>
        <p className="muted">{t('settings.mcp.env.hint')}</p>
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
          {MCP_ENV_ROWS.map((row) => (
            <tr key={row.name}>
              <td className="mono">{row.name}</td>
              <td>{t(row.meaning)}</td>
              <td className="mono">{row.fallback}</td>
            </tr>
          ))}
        </Table>
      </Card>

      {/* Cross-reference, not a relocation. API keys authenticate every integration client, not
          only MCP, so they keep their own single writer and this tab only says where it is. */}
      <Card title={t('settings.mcp.related.title')}>
        <dl className="deflist deflist--tight">
          <div>
            <dt>{t('settings.apiKeys.cardTitle')}</dt>
            <dd>{t('settings.mcp.related.apiKeys')}</dd>
          </div>
        </dl>
        <div className="row-wrap">
          <ButtonLink to="/settings/operations/api-keys" icon={<Icon.Seal />}>
            {t('settings.apiKeys.cardTitle')}
          </ButtonLink>
        </div>
      </Card>
    </div>
  );
}
