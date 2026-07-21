/**
 * Operações › Redis (t105) — the optional cache-aside and cluster shared-state surface.
 *
 * Read-only for the same three reasons as the database pane, plus one specific to Redis: on
 * PostgreSQL/HA the shared-state backend is not optional but *load-bearing*. Sessions, the global
 * rate limiter and the cross-node invalidation bus all live there, and `AppState::try_from_env`
 * refuses to start a Postgres instance whose session backend is not Redis. Repointing that from a
 * settings page would, at best, do nothing until a restart and, at worst, be a way to move every
 * session in the cluster onto a different authority from a browser.
 *
 * `REDIS_URL` carries a password in any deployment where Redis is authenticated, so — exactly as
 * with `DATABASE_URL` and the SMTP relay password — the variable is named and explained here and
 * its value is never fetched, rendered or logged. What the pane shows instead is the *classification*
 * the server already publishes: which backend kind is active, and therefore whether the cache and
 * the shared-state facilities are enabled at all.
 *
 * Note the asymmetry the copy has to carry: the cache is deliberately **fail-open** (a well-formed
 * but unreachable `REDIS_URL` still builds, and a cache miss is just a miss), whereas the
 * shared-state requirement on Postgres is **fail-closed** at startup. Presenting them as one
 * "Redis on/off" switch would flatten a distinction an operator debugging an outage needs.
 */
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { ButtonLink, Card, Icon, InlineWarning, Table } from '../../ui';

/** Transcribed from `chancela-api/src/cache.rs` and `chancela-api/src/cluster_shared_state.rs`.
 *  Both resolve from the environment once, during `AppState::try_from_env`. */
const CACHE_ENV_ROWS: readonly {
  name: string;
  meaning: MessageKey;
  fallback: string;
  secret?: boolean;
}[] = [
  { name: 'REDIS_URL', meaning: 'settings.cache.env.url', fallback: '—', secret: true },
  { name: 'REDIS_URL_FILE', meaning: 'settings.cache.env.urlFile', fallback: '—', secret: true },
  { name: 'CHANCELA_CACHE', meaning: 'settings.cache.env.cache', fallback: '—' },
];

/** The cluster tunables. Whole-second intervals, each clamped to a >= 1s minimum by
 *  `env_duration_secs` so a misconfigured value can never busy-spin a poll loop. */
const CLUSTER_ENV_ROWS: readonly { name: string; meaning: MessageKey; fallback: string }[] = [
  { name: 'CHANCELA_NODE_ROLE', meaning: 'settings.cache.env.nodeRole', fallback: '—' },
  { name: 'CHANCELA_PROMOTE_POLL_INTERVAL', meaning: 'settings.cache.env.promotePoll', fallback: '1' },
  { name: 'CHANCELA_HEARTBEAT_INTERVAL', meaning: 'settings.cache.env.heartbeat', fallback: '2' },
  {
    name: 'CHANCELA_CHANGEFEED_POLL_INTERVAL',
    meaning: 'settings.cache.env.changefeedPoll',
    fallback: '1',
  },
  {
    name: 'CHANCELA_LEADER_WATCHDOG_INTERVAL',
    meaning: 'settings.cache.env.watchdog',
    fallback: '1',
  },
  { name: 'CHANCELA_NODE_STALE_AFTER', meaning: 'settings.cache.env.staleAfter', fallback: '—' },
  { name: 'CHANCELA_CLUSTER_WRITE_MODE', meaning: 'settings.cache.env.writeMode', fallback: '—' },
];

const LOGS_TAB_PATH = '/settings/operations/logs';

export function CacheSection() {
  const t = useT();

  return (
    <div className="stack">
      <Card title={t('settings.cache.cardTitle')}>
        <div className="form settings-rows">
          <p className="field__hint">{t('settings.cache.intro')}</p>
          <InlineWarning tone="info" title={t('settings.database.readOnly.title')}>
            {t('settings.cache.readOnly.body')}
          </InlineWarning>
        </div>
      </Card>

      <Card title={t('settings.cache.env.title')}>
        <p className="muted">{t('settings.cache.env.hint')}</p>
        <Table
          caption={t('settings.cache.env.title')}
          head={
            <tr>
              <th scope="col">{t('settings.env.col.variable')}</th>
              <th scope="col">{t('settings.env.col.meaning')}</th>
              <th scope="col">{t('settings.env.col.default')}</th>
            </tr>
          }
        >
          {CACHE_ENV_ROWS.map((row) => (
            <tr key={row.name}>
              <td className="mono">{row.name}</td>
              <td>
                {t(row.meaning)}
                {row.secret ? <> {t('settings.env.secretNote')}</> : null}
              </td>
              <td className="mono">{row.fallback}</td>
            </tr>
          ))}
        </Table>
      </Card>

      <Card title={t('settings.cache.cluster.title')}>
        <p className="muted">{t('settings.cache.cluster.hint')}</p>
        <Table
          caption={t('settings.cache.cluster.title')}
          head={
            <tr>
              <th scope="col">{t('settings.env.col.variable')}</th>
              <th scope="col">{t('settings.env.col.meaning')}</th>
              <th scope="col">{t('settings.env.col.default')}</th>
            </tr>
          }
        >
          {CLUSTER_ENV_ROWS.map((row) => (
            <tr key={row.name}>
              <td className="mono">{row.name}</td>
              <td>{t(row.meaning)}</td>
              <td className="mono">{row.fallback}</td>
            </tr>
          ))}
        </Table>
      </Card>

      <Card title={t('settings.database.related.title')}>
        <dl className="deflist deflist--tight">
          <div>
            <dt>{t('settings.platform.logging.cardTitle')}</dt>
            <dd>{t('settings.cache.related.logging')}</dd>
          </div>
        </dl>
        <div className="row-wrap">
          <ButtonLink to={LOGS_TAB_PATH} icon={<Icon.Layers />}>
            {t('settings.platform.tab.logs')}
          </ButtonLink>
        </div>
      </Card>
    </div>
  );
}
