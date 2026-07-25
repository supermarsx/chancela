/**
 * Read-only presentation for the desktop-local Cartão de Cidadão bridge.
 *
 * This deliberately owns no transport, credentials, or signing request state. The host page
 * obtains the sanitized bridge status/probe DTOs and passes them in, which keeps the diagnostic
 * surface usable both from the desktop settings page and in isolated tests. In particular, this
 * panel must never grow a credential input: the bridge test accepts no request body and only
 * signs a fresh, in-memory challenge on the local card.
 */
import { Badge, Button, Card, ErrorNote, Icon, InlineWarning, Table } from '../../ui';
import { useCitizenCardBridgeT } from './CitizenCardBridgeFallback';

export type CitizenCardBridgeCheckStatus =
  'ready' | 'unavailable' | 'error' | 'not_checked' | 'injected';

/** Mirrors the intentionally non-secret `CcBridgeCheck` wire shape. */
export interface CitizenCardBridgeCheck {
  status: CitizenCardBridgeCheckStatus | string;
  code?: string | null;
  detail?: string | null;
}

/** Mirrors `GET /v1/signature/cc/bridge/status`, without coupling this component to API hooks. */
export interface CitizenCardBridgeStatus {
  transport: string;
  checked_at: string;
  local_desktop: boolean;
  diagnostic_source: string;
  middleware: CitizenCardBridgeCheck;
  pcsc: CitizenCardBridgeCheck;
  readers: CitizenCardBridgeCheck;
  reader_count: number | null;
  card: CitizenCardBridgeCheck;
  signing_certificate: CitizenCardBridgeCheck;
  issuer: CitizenCardBridgeCheck;
  ready: boolean;
  probe_supported: boolean;
  document_signed: boolean;
  persisted: boolean;
  ledger_event_written: boolean;
  qualified_status_claimed: boolean;
}

/** Mirrors `POST /v1/signature/cc/bridge/test`, again keeping all secrets out of the UI contract. */
export interface CitizenCardBridgeProbe {
  outcome: 'passed' | 'failed' | string;
  signature_verified: boolean;
  algorithm?: string | null;
  signing_certificate_present: boolean;
  issuer_resolved: boolean;
  tested_at: string;
  error?: { code: string; detail: string } | null;
  document_signed: boolean;
  persisted: boolean;
  document_ledger_event_written: boolean;
  security_audit_intent_recorded: boolean;
  security_audit_outcome_recorded: boolean;
  qualified_status_claimed: boolean;
}

export interface CitizenCardBridgeDiagnosticsProps {
  /** `null` is the initial/loading state; an error is supplied separately. */
  status?: CitizenCardBridgeStatus | null;
  statusError?: unknown;
  isRefreshing?: boolean;
  onRefresh: () => void;
  probe?: CitizenCardBridgeProbe | null;
  probeError?: unknown;
  isTesting?: boolean;
  /** Set by the host from `signing.configure` + `signing.perform`. */
  canTest?: boolean;
  onTest: () => void;
}

type BadgeTone = 'neutral' | 'accent' | 'warn' | 'error' | 'ok';
type CitizenCardBridgeT = ReturnType<typeof useCitizenCardBridgeT>;

function checkTone(status: CitizenCardBridgeCheckStatus | string): BadgeTone {
  if (status === 'ready') return 'ok';
  if (status === 'injected') return 'accent';
  if (status === 'error') return 'error';
  if (status === 'unavailable') return 'warn';
  return 'neutral';
}

function checkLabel(status: CitizenCardBridgeCheckStatus | string, t: CitizenCardBridgeT): string {
  if (status === 'ready') return t('ccBridge.status.ready');
  if (status === 'unavailable') return t('ccBridge.status.unavailable');
  if (status === 'error') return t('ccBridge.status.error');
  if (status === 'not_checked') return t('ccBridge.status.notChecked');
  if (status === 'injected') return t('ccBridge.status.injected');
  return status;
}

function transportLabel(transport: string, t: CitizenCardBridgeT): string {
  if (transport === 'embedded_loopback') return t('ccBridge.transport.local');
  return transport;
}

function readinessCheck(
  status: CitizenCardBridgeStatus,
  t: CitizenCardBridgeT,
): CitizenCardBridgeCheck {
  return status.ready
    ? {
        status: 'ready',
        detail: t('ccBridge.ready.ready'),
      }
    : {
        status: 'not_checked',
        detail: t('ccBridge.ready.unavailable'),
      };
}

function CheckCell({ check, t }: { check: CitizenCardBridgeCheck; t: CitizenCardBridgeT }) {
  return (
    <>
      <Badge tone={checkTone(check.status)}>{checkLabel(check.status, t)}</Badge>
      {check.detail ? <p className="field__hint">{check.detail}</p> : null}
      {check.code ? <p className="field__hint mono">{check.code}</p> : null}
    </>
  );
}

function DesktopCheck({ local, t }: { local: boolean; t: CitizenCardBridgeT }) {
  const check: CitizenCardBridgeCheck = local
    ? {
        status: 'ready',
        detail: t('ccBridge.desktop.ready'),
      }
    : {
        status: 'unavailable',
        detail: t('ccBridge.desktop.unavailable'),
      };
  return <CheckCell check={check} t={t} />;
}

function ProbeResult({ probe, t }: { probe: CitizenCardBridgeProbe; t: CitizenCardBridgeT }) {
  const passed = probe.outcome === 'passed' && probe.signature_verified;
  return (
    <section className="stack--tight" aria-live="polite" data-testid="cc-bridge-probe-result">
      <div>
        <Badge tone={passed ? 'ok' : 'error'}>
          {passed ? t('ccBridge.probe.passed') : t('ccBridge.probe.failed')}
        </Badge>
      </div>
      <p>{passed ? t('ccBridge.probe.passedBody') : t('ccBridge.probe.failedBody')}</p>
      <Table
        caption={t('ccBridge.probe.caption')}
        head={
          <tr>
            <th scope="col">{t('ccBridge.probe.check')}</th>
            <th scope="col">{t('ccBridge.probe.result')}</th>
          </tr>
        }
      >
        <tr>
          <th scope="row">{t('ccBridge.probe.signatureVerified')}</th>
          <td>
            <Badge tone={probe.signature_verified ? 'ok' : 'error'}>
              {probe.signature_verified ? t('ccBridge.yes') : t('ccBridge.no')}
            </Badge>
          </td>
        </tr>
        <tr>
          <th scope="row">{t('ccBridge.probe.certificate')}</th>
          <td>
            {probe.signing_certificate_present
              ? t('ccBridge.available')
              : t('ccBridge.unavailable')}
          </td>
        </tr>
        <tr>
          <th scope="row">{t('ccBridge.probe.issuer')}</th>
          <td>{probe.issuer_resolved ? t('ccBridge.yes') : t('ccBridge.no')}</td>
        </tr>
        <tr>
          <th scope="row">{t('ccBridge.probe.securityAudit')}</th>
          <td>
            {probe.security_audit_intent_recorded && probe.security_audit_outcome_recorded
              ? t('ccBridge.probe.securityAuditRecorded')
              : t('ccBridge.probe.securityAuditMissing')}
          </td>
        </tr>
        <tr>
          <th scope="row">{t('ccBridge.probe.documentLedger')}</th>
          <td>
            {probe.document_ledger_event_written
              ? t('ccBridge.probe.documentLedgerWritten')
              : t('ccBridge.probe.documentLedgerNotWritten')}
          </td>
        </tr>
        {probe.algorithm ? (
          <tr>
            <th scope="row">{t('ccBridge.probe.algorithm')}</th>
            <td className="mono">{probe.algorithm}</td>
          </tr>
        ) : null}
        {probe.error ? (
          <tr>
            <th scope="row">{t('ccBridge.probe.diagnostic')}</th>
            <td>
              <span className="mono">{probe.error.code}</span>
              <p className="field__hint">{probe.error.detail}</p>
            </td>
          </tr>
        ) : null}
      </Table>
    </section>
  );
}

/**
 * A table-like, non-secret diagnostic panel for the desktop-local Cartão de Cidadão bridge.
 * The callbacks are intentionally parameterless: neither refresh nor test accepts credentials,
 * a document, or a persistence choice.
 */
export function CitizenCardBridgeDiagnostics({
  status = null,
  statusError,
  isRefreshing = false,
  onRefresh,
  probe = null,
  probeError,
  isTesting = false,
  canTest = true,
  onTest,
}: CitizenCardBridgeDiagnosticsProps) {
  const t = useCitizenCardBridgeT();
  // A probe establishes local key usability, not issuer/TSL readiness. It stays available when
  // the trust chain is incomplete, as long as the desktop bridge can safely exercise the key.
  const testUnavailable = !status?.local_desktop || !status?.probe_supported;
  const testDisabled = isTesting || !canTest || testUnavailable;

  return (
    <section className="stack" aria-labelledby="cc-bridge-diagnostics-title">
      <Card
        title={<span id="cc-bridge-diagnostics-title">{t('ccBridge.title')}</span>}
        actions={
          <div className="rowline">
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Refresh />}
              disabled={isRefreshing}
              onClick={() => onRefresh()}
            >
              {isRefreshing ? t('ccBridge.refreshPending') : t('ccBridge.refresh')}
            </Button>
            <Button
              type="button"
              variant="primary"
              icon={<Icon.Check />}
              disabled={testDisabled}
              aria-describedby="cc-bridge-test-boundary"
              onClick={() => onTest()}
            >
              {isTesting ? t('ccBridge.testPending') : t('ccBridge.test')}
            </Button>
          </div>
        }
      >
        <p>{t('ccBridge.intro')}</p>
        <InlineWarning tone="info" title={t('ccBridge.boundary.title')}>
          <p id="cc-bridge-test-boundary">{t('ccBridge.boundary.body')}</p>
        </InlineWarning>

        {!canTest ? (
          <p className="field__hint" role="status">
            {t('ccBridge.permissions')}
          </p>
        ) : null}
        {testUnavailable && status ? (
          <p className="field__hint" role="status">
            {t('ccBridge.testUnavailable')}
          </p>
        ) : null}
        {statusError ? <ErrorNote error={statusError} /> : null}

        {status ? (
          <Table
            caption={t('ccBridge.table.caption')}
            className="cc-bridge-diagnostics-table"
            head={
              <tr>
                <th scope="col">{t('ccBridge.table.component')}</th>
                <th scope="col">{t('ccBridge.table.status')}</th>
              </tr>
            }
          >
            <tr>
              <th scope="row">{t('ccBridge.desktop')}</th>
              <td>
                <DesktopCheck local={status.local_desktop} t={t} />
                <p className="field__hint">{transportLabel(status.transport, t)}</p>
              </td>
            </tr>
            <tr>
              <th scope="row">{t('ccBridge.checkedAt')}</th>
              <td>
                <time dateTime={status.checked_at}>{status.checked_at}</time>
              </td>
            </tr>
            <tr>
              <th scope="row">{t('ccBridge.middleware')}</th>
              <td>
                <CheckCell check={status.middleware} t={t} />
              </td>
            </tr>
            <tr>
              <th scope="row">{t('ccBridge.pcsc')}</th>
              <td>
                <CheckCell check={status.pcsc} t={t} />
              </td>
            </tr>
            <tr>
              <th scope="row">{t('ccBridge.readers')}</th>
              <td>
                <CheckCell check={status.readers} t={t} />
                {status.reader_count !== null ? (
                  <p className="field__hint">
                    {t('ccBridge.readerCount', { count: status.reader_count })}
                  </p>
                ) : null}
              </td>
            </tr>
            <tr>
              <th scope="row">{t('ccBridge.card')}</th>
              <td>
                <CheckCell check={status.card} t={t} />
              </td>
            </tr>
            <tr>
              <th scope="row">{t('ccBridge.certificate')}</th>
              <td>
                <CheckCell check={status.signing_certificate} t={t} />
              </td>
            </tr>
            <tr>
              <th scope="row">{t('ccBridge.issuer')}</th>
              <td>
                <CheckCell check={status.issuer} t={t} />
              </td>
            </tr>
            <tr>
              <th scope="row">{t('ccBridge.readiness')}</th>
              <td>
                <CheckCell check={readinessCheck(status, t)} t={t} />
              </td>
            </tr>
          </Table>
        ) : !statusError ? (
          <p className="field__hint" role="status">
            {t('ccBridge.empty')}
          </p>
        ) : null}

        {probeError ? <ErrorNote error={probeError} /> : null}
        {probe ? <ProbeResult probe={probe} t={t} /> : null}
      </Card>
    </section>
  );
}
