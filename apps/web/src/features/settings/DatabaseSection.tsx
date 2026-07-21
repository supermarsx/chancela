/**
 * Operações › Base de dados (t105) — the durable-store configuration surface.
 *
 * ## Why this pane has no editor
 *
 * The user asked for "some degree of configurability" for the database. The honest degree turned
 * out to be zero, and the reason is worth stating rather than papering over with a form:
 *
 * 1. **Every one of these values is read exactly once, at process start.** The backend selection,
 *    the connection string, the SQLCipher key source and the sidecar storage mode are all resolved
 *    inside `AppState::try_from_env` before the first request is served, and nothing re-reads them.
 *    A text field wired to `PUT /v1/settings` would accept a value, report success, and change
 *    nothing until someone restarted the process — which is worse than no field, because it looks
 *    like it worked.
 * 2. **There is no runtime-safe subset to carve out.** Pool sizes, statement timeouts and connect
 *    timeouts are the usual candidates; this codebase does not expose any of them, so there is
 *    nothing here that could be changed live even in principle. What IS runtime-changeable about
 *    the database — its log level — already has a control, on Operações › Registos, and this pane
 *    links to it rather than growing a second writer for the same field.
 * 3. **The failure mode is catastrophic and silent-adjacent.** An editable connection string on a
 *    settings page is a way to point a running instance at an empty database, or at another
 *    instance's, from a browser. Restarting the server to apply a settings change is not something
 *    a settings page should be able to do either.
 *
 * So this is a table of facts, exactly like the launch-time block on the API pane, and it says
 * where each value comes from so an operator knows which file to edit and what to restart.
 *
 * ## Secrets
 *
 * `DATABASE_URL` embeds a password in the overwhelming majority of real deployments, and
 * `CHANCELA_DB_KEY` is a SQLCipher passphrase. **Neither is ever fetched, rendered, or logged** —
 * this pane names the variables and describes what they do, and takes its live state from
 * `GET /v1/data/status`, which reports encryption posture and backend family as classifications
 * (`postgres`/`sqlite`, key-source class) and never as strings. That mirrors the SMTP relay: the
 * settings document holds the non-secret parts, the secret itself lives elsewhere, and only a
 * classification escapes to the client.
 */
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { ButtonLink, Card, Icon, InlineWarning, Table } from '../../ui';

/** The launch-time environment surface, transcribed from `chancela-api/src/database.rs`. Every row
 *  is resolved once in `AppState::try_from_env`; none is writable by any endpoint. */
const DATABASE_ENV_ROWS: readonly {
  name: string;
  meaning: MessageKey;
  fallback: string;
  /** Rows whose value is or contains a credential. Named and explained, never displayed. */
  secret?: boolean;
}[] = [
  { name: 'CHANCELA_DB_BACKEND', meaning: 'settings.database.env.backend', fallback: 'sqlite' },
  { name: 'DATABASE_URL', meaning: 'settings.database.env.url', fallback: '—', secret: true },
  {
    name: 'DATABASE_URL_FILE',
    meaning: 'settings.database.env.urlFile',
    fallback: '—',
    secret: true,
  },
  { name: 'CHANCELA_DATA_DIR', meaning: 'settings.database.env.dataDir', fallback: '—' },
  { name: 'CHANCELA_DB_KEY', meaning: 'settings.database.env.key', fallback: '—', secret: true },
  {
    name: 'CHANCELA_DB_KEY_FILE',
    meaning: 'settings.database.env.keyFile',
    fallback: '—',
    secret: true,
  },
  { name: 'CHANCELA_DB_KEY_SOURCE', meaning: 'settings.database.env.keySource', fallback: 'operator' },
  { name: 'CHANCELA_PG_SSLMODE', meaning: 'settings.database.env.sslMode', fallback: '—' },
];

const LOGS_TAB_PATH = '/settings/operations/logs';
const DATA_TAB_PATH = '/settings/operations/data';

export function DatabaseSection() {
  const t = useT();

  return (
    <div className="stack">
      <Card title={t('settings.database.cardTitle')}>
        <div className="form settings-rows">
          <p className="field__hint">{t('settings.database.intro')}</p>
          <InlineWarning tone="info" title={t('settings.database.readOnly.title')}>
            {t('settings.database.readOnly.body')}
          </InlineWarning>
        </div>
      </Card>

      <Card title={t('settings.env.title')}>
        <p className="muted">{t('settings.database.env.hint')}</p>
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
          {DATABASE_ENV_ROWS.map((row) => (
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

      {/* Cross-references rather than relocations: each of these already has exactly one writer,
          and duplicating a control here would let two screens disagree about one value. */}
      <Card title={t('settings.database.related.title')}>
        <dl className="deflist deflist--tight">
          <div>
            <dt>{t('settings.platform.logging.cardTitle')}</dt>
            <dd>{t('settings.database.related.logging')}</dd>
          </div>
          <div>
            <dt>{t('data.cardTitle')}</dt>
            <dd>{t('settings.database.related.dataStatus')}</dd>
          </div>
        </dl>
        <div className="row-wrap">
          <ButtonLink to={LOGS_TAB_PATH} icon={<Icon.Layers />}>
            {t('settings.platform.tab.logs')}
          </ButtonLink>
          <ButtonLink to={DATA_TAB_PATH} icon={<Icon.Archive />}>
            {t('data.cardTitle')}
          </ButtonLink>
        </div>
      </Card>
    </div>
  );
}
