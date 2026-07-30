/**
 * Administração › Diagnóstico — every diagnostic fact this instance already publishes, on one
 * screen, with three ways to take it away: clipboard, printer, `.txt`.
 *
 * ─── WHAT IT IS FOR ────────────────────────────────────────────────────────────────────────────
 *
 * The panes around it each answer one question well (Serviços, Base de dados, Redis, Ambiente do
 * servidor, Armazenamento, Pesquisa, Confiança, Email). During an incident an operator needs all of
 * them at once, in a form they can paste into a ticket. This pane ASSEMBLES; it probes nothing new
 * and adds no endpoint. Every row comes from a route that already exists and already carries its
 * own permission gate.
 *
 * ─── HONESTY IS THE FEATURE ────────────────────────────────────────────────────────────────────
 *
 * A diagnostics screen is the one screen an operator trusts during an outage, so it must never
 * print a status it did not read. Each source renders its own state — `ok`, `loading`, `forbidden`,
 * `error:<code>` — and a source that did not answer renders its declared fields as an explicit
 * «Não verificado», never as a blank and never as a pass. There is no optimistic default anywhere
 * in {@link buildDiagnosticsReport}; see its header for the three rules it enforces by construction
 * (no secret, no personal data, no unread status).
 *
 * ─── SCREEN AND EXPORT CANNOT DRIFT ────────────────────────────────────────────────────────────
 *
 * Both render {@link DiagnosticsReport}. The table below walks `report.sections`; the clipboard,
 * the file and (through the DOM) the printed sheet all serialise the same object. A section added
 * to the model appears in all four without another edit, which is the only arrangement in which
 * "the export is complete" stays true a month from now.
 *
 * ─── LOCALE ────────────────────────────────────────────────────────────────────────────────────
 *
 * Field ids are machine identifiers and stay verbatim in all fourteen locales — the same rule the
 * Ambiente do servidor pane applies to `CHANCELA_*` names. Only the chrome around them is
 * translated. The `.txt` therefore contains no prose at all: two operators comparing dumps
 * generated in pt-PT and fi-FI are comparing the same bytes.
 */
import { useMemo, useState } from 'react';
import { ApiError } from '../../api/client';
import {
  useDataStatus,
  useEmailDeliveries,
  useEmailStatus,
  useHealth,
  useLedgerIntegrity,
  usePlatformServices,
  useProviderCredentials,
  useSearchStatus,
  useServerEnv,
  useSettings,
  useTrustStatus,
  useZkStorageStatus,
} from '../../api/hooks';
import { UI_VERSION } from '../../api/versionCheck';
import { isTauri } from '../../desktop/tauri';
import { saveBlobAs } from '../../desktop/saveFile';
import { useActiveLocale, useT } from '../../i18n';
import { PermissionDeniedNote, useCan } from '../session/permissions';
import { Badge, Button, Card, Icon, InlineWarning, SkeletonTable, Table, useToast } from '../../ui';
import { BUILD_COMMIT } from './buildProvenance';
import {
  buildDiagnosticsReport,
  diagnosticsFilename,
  renderDiagnosticsText,
  type DiagnosticRow,
  type DiagnosticSection,
  type DiagnosticSourceState,
  type DiagnosticValue,
  type DiagnosticsSource,
} from './diagnosticsReport';
import './diagnostics.css';

/** The body class the print rules key off — the `printing-doc` / `printing-validation` idiom. */
const PRINT_CLASS = 'printing-diagnostics';

/** The subtree print isolates. Also the export's DOM anchor for the tests. */
const REPORT_CLASS = 'diagnostics-report';

/** The MIME the `.txt` is written with. UTF-8 is explicit: the report can carry any host name. */
const TEXT_MIME = 'text/plain;charset=utf-8';

/** The shape of every query this pane reads, narrowed to what the state mapping needs. */
interface QueryLike<T> {
  data: T | undefined;
  error: unknown;
  fetchStatus: 'fetching' | 'paused' | 'idle';
}

/**
 * Map one query onto an honest source state.
 *
 * A 403 becomes `forbidden` rather than a generic error because it is not a fault: this pane
 * aggregates routes with different gates (`ledger.read`, `search.read`, `settings.read`), so a
 * principal legitimately sees some sections refused. Anything else keeps its HTTP status as the
 * code; a transport failure that never reached the server is `network`. A query that has neither
 * answered nor failed nor is in flight is reported as not checked, never as empty.
 */
function toSourceState<T>(query: QueryLike<T>): DiagnosticSourceState {
  if (query.error !== null && query.error !== undefined) {
    if (query.error instanceof ApiError) {
      if (query.error.status === 403) return { kind: 'forbidden' };
      return { kind: 'error', code: String(query.error.status) };
    }
    return { kind: 'error', code: 'network' };
  }
  if (query.data !== undefined) return { kind: 'ok' };
  if (query.fetchStatus === 'fetching') return { kind: 'loading' };
  return { kind: 'not_checked', reason: 'no_response' };
}

function toSource<T>(query: QueryLike<T>): DiagnosticsSource<T> {
  return { state: toSourceState(query), data: query.data };
}

/** The resolved IANA zone, or `null` when the runtime cannot name one. Never guessed. */
function resolveTimeZone(): string | null {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  } catch {
    return null;
  }
}

/** The host this instance is served from — the filename's instance discriminator. */
function resolveHost(): string {
  if (typeof window === 'undefined') return 'instance';
  return window.location.host || window.location.hostname || 'instance';
}

/**
 * Print just the report: toggle `body.printing-diagnostics` so the rules in `diagnostics.css`
 * isolate the report subtree, then open the platform dialog. The class is removed on `afterprint`,
 * and the whole thing is a no-op in an environment without `print` (jsdom, an embedded webview
 * without a print service) rather than throwing.
 */
function printReport(): boolean {
  if (typeof window === 'undefined' || typeof window.print !== 'function') return false;
  document.body.classList.add(PRINT_CLASS);
  const cleanup = () => {
    document.body.classList.remove(PRINT_CLASS);
    window.removeEventListener('afterprint', cleanup);
  };
  window.addEventListener('afterprint', cleanup);
  window.print();
  return true;
}

export function DiagnosticsSection() {
  const t = useT();
  const toast = useToast();
  const can = useCan();
  const locale = useActiveLocale();
  const allowed = can('settings.read') || can('settings.manage');

  const health = useHealth();
  const services = usePlatformServices();
  const env = useServerEnv();
  const storage = useDataStatus();
  const zk = useZkStorageStatus();
  const ledger = useLedgerIntegrity();
  // The one source with its own poll. Left as it is rather than forked: the pane must show what
  // the Pesquisa panel shows, and a second query shape would eventually disagree with it.
  const search = useSearchStatus();
  const trust = useTrustStatus();
  const email = useEmailStatus();
  const deliveries = useEmailDeliveries();
  const credentials = useProviderCredentials();
  const settings = useSettings();

  /** The last export failure, shown in place rather than swallowed. */
  const [actionError, setActionError] = useState<'copy' | 'download' | 'print' | null>(null);

  // The report is rebuilt whenever any source moves, and its timestamp moves with it — a fixed
  // "generated at" over live data would be a lie the moment the first poll landed.
  const report = useMemo(
    () =>
      buildDiagnosticsReport({
        generatedAt: new Date(),
        locale,
        timeZone: resolveTimeZone(),
        uiVersion: UI_VERSION,
        build: BUILD_COMMIT,
        desktop: isTauri(),
        host: resolveHost(),
        health: toSource(health),
        services: toSource(services),
        env: toSource(env),
        storage: toSource(storage),
        zk: toSource(zk),
        ledger: toSource(ledger),
        search: toSource(search),
        trust: toSource(trust),
        email: toSource(email),
        deliveries: toSource(deliveries),
        credentials: toSource(credentials),
        settingsSchemaVersion: {
          state: toSourceState(settings),
          data: settings.data?.schema_version,
        },
      }),
    // Every source is a dependency by its data/error/fetchStatus triple; listing the query objects
    // themselves would rebuild on every render (react-query returns a fresh wrapper each time).
    /* eslint-disable react-hooks/exhaustive-deps */
    [
      locale,
      health.data,
      health.error,
      health.fetchStatus,
      services.data,
      services.error,
      services.fetchStatus,
      env.data,
      env.error,
      env.fetchStatus,
      storage.data,
      storage.error,
      storage.fetchStatus,
      zk.data,
      zk.error,
      zk.fetchStatus,
      ledger.data,
      ledger.error,
      ledger.fetchStatus,
      search.data,
      search.error,
      search.fetchStatus,
      trust.data,
      trust.error,
      trust.fetchStatus,
      email.data,
      email.error,
      email.fetchStatus,
      deliveries.data,
      deliveries.error,
      deliveries.fetchStatus,
      credentials.data,
      credentials.error,
      credentials.fetchStatus,
      settings.data,
      settings.error,
      settings.fetchStatus,
    ],
    /* eslint-enable react-hooks/exhaustive-deps */
  );

  // ONE serialisation, shared by the clipboard and the file, so the two can never differ by a byte.
  const reportText = useMemo(() => renderDiagnosticsText(report), [report]);

  if (!allowed) {
    return (
      <Card title={t('settings.diagnostics.title')}>
        <PermissionDeniedNote />
      </Card>
    );
  }

  async function copyReport() {
    if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) {
      // An insecure context or a permissions policy without clipboard-write. Visible, never silent:
      // the operator needs to know to select the table instead.
      setActionError('copy');
      return;
    }
    try {
      await navigator.clipboard.writeText(reportText);
      setActionError(null);
      toast.success(t('settings.diagnostics.copied'));
    } catch {
      setActionError('copy');
    }
  }

  async function downloadReport() {
    const filename = diagnosticsFilename(resolveHost(), new Date());
    try {
      // `saveBlobAs` is the codebase's save idiom: a native dialog under Tauri, the File System
      // Access picker where offered, and otherwise an object-URL anchor it revokes immediately.
      // Nothing here reaches the network — the bytes are assembled in the tab.
      const result = await saveBlobAs({
        blob: new Blob([reportText], { type: TEXT_MIME }),
        filename,
        contentType: TEXT_MIME,
      });
      if (result.kind === 'cancelled') return;
      setActionError(null);
      toast.success(t('settings.diagnostics.downloaded', { filename: result.filename }));
    } catch {
      setActionError('download');
    }
  }

  function print() {
    if (!printReport()) {
      setActionError('print');
      return;
    }
    setActionError(null);
  }

  return (
    <div className="stack">
      <Card
        title={t('settings.diagnostics.title')}
        actions={
          <div className="row-wrap">
            <Button variant="secondary" icon={<Icon.Copy />} onClick={() => void copyReport()}>
              {t('settings.diagnostics.copy')}
            </Button>
            <Button variant="secondary" icon={<Icon.Printer />} onClick={print}>
              {t('common.print')}
            </Button>
            <Button variant="primary" icon={<Icon.Save />} onClick={() => void downloadReport()}>
              {t('settings.diagnostics.download')}
            </Button>
          </div>
        }
      >
        <div className="stack--tight">
          <p className="field__hint">{t('settings.diagnostics.intro')}</p>
          <p className="field__hint">{t('settings.diagnostics.privacyNote')}</p>
          <p className="field__hint">{t('settings.diagnostics.unknownNote')}</p>
          {actionError !== null ? (
            <InlineWarning tone="error" title={t('settings.diagnostics.actionFailed')}>
              {actionError === 'copy'
                ? t('settings.diagnostics.copyFailed')
                : actionError === 'download'
                  ? t('settings.diagnostics.downloadFailed')
                  : t('settings.diagnostics.printFailed')}
            </InlineWarning>
          ) : null}
        </div>
      </Card>

      {/* The print-isolated subtree. It also carries the generated-at stamp as ordinary text so a
          printed sheet is self-describing without the screen chrome around it.

          `stack` because the section cards need a gap between them and nothing else supplies one:
          they are grandchildren of the surrounding card body, so the container rhythm does not
          reach them, and without an owner here they render edge to edge. */}
      <div className={`stack ${REPORT_CLASS}`} data-generated-at={report.generatedAt}>
        {report.sections.map((section) => (
          <DiagnosticsSectionCard key={section.id} section={section} />
        ))}
      </div>
    </div>
  );
}

function DiagnosticsSectionCard({ section }: { section: DiagnosticSection }) {
  const t = useT();
  return (
    <Card
      className="diagnostics-card"
      title={t(section.titleKey)}
      actions={<SourceBadge state={section.source} />}
    >
      {section.source.kind === 'loading' && section.rows.length === 0 ? (
        <SkeletonTable rows={3} cols={2} />
      ) : (
        <Table
          className="diagnostics-table"
          caption={t('settings.diagnostics.tableCaption', { section: t(section.titleKey) })}
          head={
            <tr>
              <th scope="col">{t('settings.diagnostics.column.field')}</th>
              <th scope="col">{t('settings.diagnostics.column.value')}</th>
            </tr>
          }
        >
          {section.rows.map((row) => (
            <DiagnosticsRow key={row.id} section={section.id} row={row} />
          ))}
        </Table>
      )}
    </Card>
  );
}

function DiagnosticsRow({ section, row }: { section: string; row: DiagnosticRow }) {
  return (
    <tr data-diagnostic-row={row.id} data-diagnostic-section={section}>
      {/* The field id is a machine identifier: monospaced, verbatim, untranslated in every locale,
          and the same token the `.txt` carries — so a row quoted from the screen is greppable in
          the export and vice versa. */}
      <th scope="row" className="mono">
        {row.id}
      </th>
      <td>
        <DiagnosticsValueCell value={row.value} />
      </td>
    </tr>
  );
}

function DiagnosticsValueCell({ value }: { value: DiagnosticValue }) {
  const t = useT();
  switch (value.kind) {
    case 'text':
      return <span className="mono">{value.text}</span>;
    case 'count':
      return <span className="mono">{String(value.value)}</span>;
    case 'bool':
      return (
        <Badge tone={value.value ? 'ok' : 'neutral'}>
          {value.value ? t('common.yes') : t('common.no')}
        </Badge>
      );
    case 'configured':
      return (
        <Badge tone={value.value ? 'ok' : 'neutral'}>
          {value.value
            ? t('settings.serverEnv.secret.configured')
            : t('settings.serverEnv.secret.notConfigured')}
        </Badge>
      );
    case 'unset':
      // Read, and genuinely unset. An em dash carries no language, so it needs no key — and it is
      // deliberately NOT what an unread field shows (that is the badge below).
      return <span className="muted">—</span>;
    case 'unknown':
      return <Badge tone="warn">{t('settings.diagnostics.value.unknown')}</Badge>;
    case 'error':
      return (
        <Badge tone="error">{t('settings.diagnostics.value.error', { code: value.code })}</Badge>
      );
  }
}

function SourceBadge({ state }: { state: DiagnosticSourceState }) {
  const t = useT();
  switch (state.kind) {
    case 'ok':
      return <Badge tone="ok">{t('settings.diagnostics.source.ok')}</Badge>;
    case 'loading':
      return <Badge tone="neutral">{t('settings.diagnostics.source.loading')}</Badge>;
    case 'not_checked':
      return (
        <Badge tone="warn">
          {t('settings.diagnostics.source.notChecked', { reason: state.reason })}
        </Badge>
      );
    case 'forbidden':
      return <Badge tone="warn">{t('settings.diagnostics.source.forbidden')}</Badge>;
    case 'error':
      // Deliberately the same key a failed FIELD uses: "Erro (403)" reads identically whether the
      // failure is one row's or the whole source's, and one sentence is one translation to review.
      return (
        <Badge tone="error">{t('settings.diagnostics.value.error', { code: state.code })}</Badge>
      );
  }
}
