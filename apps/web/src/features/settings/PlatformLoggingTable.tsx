/**
 * Compact, accessible editor/read-model for the platform logging matrix.
 *
 * Logging is one repeated relationship — scope, area level, optional service override, effective
 * level, and the source of that result — so it belongs in the shared real `<Table>` pattern rather
 * than a stack of full-width fields and bordered summary cards. Callers decide which cells are
 * editable; the component keeps the visual and accessibility contract identical on Registos, API,
 * and MCP.
 */
import { useId, type ReactNode } from 'react';
import type { PlatformLogLevel, PlatformLoggingSettings, PlatformServiceId } from '../../api/types';
import { PLATFORM_LOG_LEVELS } from '../../api/types';
import { useT, type MessageKey } from '../../i18n';
import { Badge, FieldHelp, Select, Table } from '../../ui';
import './platformLoggingTable.css';

const LOG_LEVEL_RANK: Record<PlatformLogLevel, number> = {
  trace: 0,
  debug: 1,
  info: 2,
  warn: 3,
  error: 4,
  off: 5,
};

export function logLevelOptions(t: ReturnType<typeof useT>) {
  return PLATFORM_LOG_LEVELS.map((level) => ({
    value: level,
    label: t(`settings.platform.logLevel.${level}` as MessageKey),
  }));
}

export function overrideOptions(t: ReturnType<typeof useT>) {
  return [
    { value: '', label: t('settings.platform.logging.override.none') },
    ...logLevelOptions(t),
  ];
}

function logAreaField(serviceId: PlatformServiceId): 'app' | 'api' | 'mcp' {
  if (serviceId === 'mcp_stdio') return 'mcp';
  return serviceId;
}

function stricterLogLevel(left: PlatformLogLevel, right: PlatformLogLevel): PlatformLogLevel {
  return LOG_LEVEL_RANK[left] >= LOG_LEVEL_RANK[right] ? left : right;
}

export function effectiveLogLevel(
  logging: PlatformLoggingSettings,
  serviceId: PlatformServiceId,
): PlatformLogLevel {
  if (logging.global === 'off') return 'off';
  const override = logging.service_overrides[serviceId];
  if (override) return override;
  return stricterLogLevel(logging.global, logging[logAreaField(serviceId)]);
}

export function loggingSourceText(
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

export interface PlatformLoggingLevelCell {
  /** Stable DOM id retained by existing settings tests, labels, and deep links. */
  id: string;
  /** Accessible label for the select, or the semantic name beside a read-only value. */
  label: string;
  value: PlatformLogLevel;
  /** Omit for a read-only overview cell. */
  onChange?: (level: PlatformLogLevel) => void;
}

export interface PlatformLoggingOverrideCell {
  id: string;
  label: string;
  /** Empty means the service inherits its area/global result. */
  value: PlatformLogLevel | '';
  /** Omit for a read-only overview cell. */
  onChange?: (level: PlatformLogLevel | '') => void;
}

export interface PlatformLoggingTableRow {
  id: string;
  scope: string;
  area: PlatformLoggingLevelCell;
  /**
   * `null` means the scope cannot carry a service override (the global floor). A present cell with
   * no `onChange` is a read-only overview of an override configured on another owning tab.
   */
  override: PlatformLoggingOverrideCell | null;
  effective: PlatformLogLevel;
  source: ReactNode;
  /** Optional deep link or plain location label shown below the source calculation. */
  configuration?: ReactNode;
}

function LevelBadge({
  level,
  effective = false,
}: {
  level: PlatformLogLevel;
  effective?: boolean;
}) {
  const t = useT();
  return (
    <Badge tone={effective && level !== 'off' ? 'accent' : 'neutral'}>
      {t(`settings.platform.logLevel.${level}` as MessageKey)}
    </Badge>
  );
}

export function PlatformLoggingTable({
  caption,
  rows,
}: {
  caption: string;
  rows: readonly PlatformLoggingTableRow[];
}) {
  const t = useT();
  const levels = logLevelOptions(t);
  const overrides = overrideOptions(t);
  const levelHelpId = useId();
  const overrideHelpId = useId();

  return (
    <Table
      caption={caption}
      className="platform-logging-table"
      head={
        <tr>
          <th scope="col">{t('settings.platform.logs.column.service')}</th>
          <th scope="col">
            <span className="platform-logging-table__heading">
              {t('settings.platform.logs.column.level')}
              <FieldHelp text={t('settings.platform.help.logLevels')} describedById={levelHelpId} />
            </span>
          </th>
          <th scope="col">
            <span className="platform-logging-table__heading">
              {t('settings.platform.logging.overrides')}
              <FieldHelp
                text={t('settings.platform.help.overrides')}
                describedById={overrideHelpId}
              />
            </span>
          </th>
          <th scope="col">
            <span className="platform-logging-table__heading">
              {t('settings.platform.effectiveLog')}
              <FieldHelp text={t('settings.platform.help.effective')} />
            </span>
          </th>
          <th scope="col">{t('settings.platform.logs.retention.source')}</th>
        </tr>
      }
    >
      {rows.map((row) => (
        <tr key={row.id} data-platform-logging-row={row.id}>
          <th scope="row">{row.scope}</th>
          <td>
            {row.area.onChange ? (
              <>
                <label className="sr-only" htmlFor={row.area.id}>
                  {row.area.label}
                </label>
                <Select
                  id={row.area.id}
                  aria-describedby={levelHelpId}
                  value={row.area.value}
                  options={levels}
                  onChange={(event) => row.area.onChange?.(event.target.value as PlatformLogLevel)}
                />
              </>
            ) : (
              <LevelBadge level={row.area.value} />
            )}
          </td>
          <td>
            {row.override === null ? (
              <span
                className="platform-logging-table__not-applicable"
                aria-label={t('settings.platform.logging.override.none')}
              >
                —
              </span>
            ) : row.override.onChange ? (
              <>
                <label className="sr-only" htmlFor={row.override.id}>
                  {row.override.label}
                </label>
                <Select
                  id={row.override.id}
                  aria-describedby={overrideHelpId}
                  value={row.override.value}
                  options={overrides}
                  onChange={(event) =>
                    row.override?.onChange?.(event.target.value as PlatformLogLevel | '')
                  }
                />
              </>
            ) : row.override.value ? (
              <LevelBadge level={row.override.value} />
            ) : (
              <span className="platform-logging-table__inherited">
                {t('settings.platform.logging.override.none')}
              </span>
            )}
          </td>
          <td>
            <LevelBadge level={row.effective} effective />
          </td>
          <td>
            <div className="platform-logging-table__source">
              <span>{row.source}</span>
              {row.configuration ? (
                <span className="platform-logging-table__configuration">{row.configuration}</span>
              ) : null}
            </div>
          </td>
        </tr>
      ))}
    </Table>
  );
}
