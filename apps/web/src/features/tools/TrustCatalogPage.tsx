/**
 * TSL trust catalog surface for Ferramentas.
 *
 * Read-only by design: the backend exposes the parsed Trusted List state and catalog, but
 * no live refresh operation. The UI therefore mirrors the CAE/law consultation style:
 * a compact status card for scheme/source/signature validity, plus a two-pane catalog
 * explorer with URL-backed search/filter/selection and provider/service detail panes.
 */
import { createContext, useContext, useMemo, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  useTsaCatalog,
  useTsaCatalogSearch,
  useRefreshTrustTsl,
  useTrustCatalog,
  useTrustCatalogSearch,
  useTrustProvider,
  useTrustService,
  useTrustStatus,
} from '../../api/hooks';
import { useT, type MessageKey, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  DateTime,
  Digest,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  Input,
  Select,
  Skeleton,
  SkeletonDeflist,
  ColumnHead,
  SkeletonRegion,
  SubNav,
  Table,
  Toggle,
} from '../../ui';
import { useSectionNav } from '../../app/navPath';
import { useTrustSectionsT } from '../../i18n/trustSectionsFallback';
import type {
  TslCatalogSearchParams,
  TslCatalogView,
  TslProviderView,
  TslDigitalIdentityView,
  TslServiceHistoryView,
  TslServiceStatusKind,
  TslServiceSummaryView,
  TslSignatureStatus,
  TslSourceKind,
  TsaCatalogSearchParams,
  TsaProbeStatus,
  TsaRecordView,
  TsaStatusKind,
  TrustIdentifierMatchField,
} from '../../api/types';

type TrustFilter = 'all' | 'providers' | 'services' | 'qualified' | 'trusted' | 'caqc';
type TrustTypeFilter = 'all' | 'caqc' | 'tsa' | 'qtst' | 'other';
type TrustStatusFilter = 'all' | TslServiceStatusKind;
type TsaTypeFilter = 'all' | 'qtst' | 'tst';

const TRUST_FILTERS: TrustFilter[] = [
  'all',
  'providers',
  'services',
  'qualified',
  'trusted',
  'caqc',
];

const TRUST_TYPE_FILTERS: readonly { value: TrustTypeFilter; labelKey: MessageKey }[] = [
  { value: 'all', labelKey: 'trust.type.all' },
  { value: 'caqc', labelKey: 'trust.type.caqc' },
  { value: 'tsa', labelKey: 'trust.type.tsa' },
  { value: 'qtst', labelKey: 'trust.type.qtst' },
  { value: 'other', labelKey: 'trust.type.other' },
];

const TRUST_STATUS_FILTERS: readonly { value: TrustStatusFilter; labelKey: MessageKey }[] = [
  { value: 'all', labelKey: 'trust.statusFilter.all' },
  { value: 'Granted', labelKey: 'trust.service.status.Granted' },
  { value: 'Withdrawn', labelKey: 'trust.service.status.Withdrawn' },
  { value: 'Other', labelKey: 'trust.service.status.Other' },
];

const TSA_TYPE_FILTERS: readonly { value: TsaTypeFilter; labelKey: MessageKey }[] = [
  { value: 'all', labelKey: 'trust.tsa.type.all' },
  { value: 'qtst', labelKey: 'trust.tsa.type.qtst' },
  { value: 'tst', labelKey: 'trust.tsa.type.tst' },
];

const TRUST_SEARCH_LIMIT = 500;

function normalize(value: string): string {
  return value
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .toLowerCase();
}

function includesTerm(values: Array<string | null | undefined>, term: string): boolean {
  if (!term) return true;
  return values.some((v) => (v ? normalize(v).includes(term) : false));
}

function optionValue<T extends string>(
  value: string | null,
  options: readonly { value: T; labelKey: MessageKey }[],
  fallback: T,
): T {
  return options.some((option) => option.value === value) ? (value as T) : fallback;
}

function localizedOptions<T extends string>(
  options: readonly { value: T; labelKey: MessageKey }[],
  t: TFunction,
): { value: T; label: string }[] {
  return options.map((option) => ({ value: option.value, label: t(option.labelKey) }));
}

function hasStructuredSearchParams(params: TslCatalogSearchParams): boolean {
  return (
    !!params.search?.trim() ||
    !!params.identifier?.trim() ||
    !!params.service_type ||
    !!params.status ||
    !!params.history ||
    !!params.supply_point
  );
}

function trustServiceTypeParam(
  typeFilter: TrustTypeFilter,
  trustFilter: TrustFilter = 'all',
): string | undefined {
  if (typeFilter === 'caqc') return 'CA/QC';
  if (typeFilter === 'tsa') return 'TSA';
  if (typeFilter === 'qtst') return 'TSA/QTST';
  if (typeFilter === 'all' && trustFilter === 'caqc') return 'CA/QC';
  return undefined;
}

function tsaServiceTypeParam(typeFilter: TsaTypeFilter): string | undefined {
  if (typeFilter === 'qtst') return 'TSA/QTST';
  if (typeFilter === 'tst') return 'TSA/TST';
  return undefined;
}

function sourceLabel(kind: TslSourceKind): MessageKey {
  if (kind === 'Cache') return 'trust.source.cache';
  return 'trust.source.fixture';
}

function serviceStatusLabel(status: TslServiceStatusKind): MessageKey {
  return `trust.service.status.${status}` as MessageKey;
}

function signatureLabel(status: TslSignatureStatus): MessageKey {
  return `trust.signature.${status}` as MessageKey;
}

function filterLabel(filter: TrustFilter): MessageKey {
  return `trust.filter.${filter}` as MessageKey;
}

const IDENTIFIER_MATCH_LABELS: Record<TrustIdentifierMatchField, string> = {
  certificate_sha256: 'certificate SHA-256',
  subject_key_id: 'subject key ID',
  subject_name: 'subject name',
  provider: 'provider',
  service: 'service',
  supply_point: 'supply point',
  catalog: 'catalog text',
};

function identifierMatchText(
  fields: readonly TrustIdentifierMatchField[] | null | undefined,
): string | null {
  if (!fields?.length) return null;
  const labels = fields
    .filter((field, index) => fields.indexOf(field) === index)
    .map((field) => IDENTIFIER_MATCH_LABELS[field] ?? field.replace(/_/g, ' '));
  if (!labels.length) return null;
  return `Matched by technical catalog identifier only: ${labels.join(', ')}`;
}

function IdentifierMatchNote({
  fields,
}: {
  fields: readonly TrustIdentifierMatchField[] | null | undefined;
}) {
  const text = identifierMatchText(fields);
  if (!text) return null;
  return (
    <span className="trust-pick__meta muted" title={text}>
      {text}
    </span>
  );
}

function isDigestIdentity(value: string): boolean {
  return (value.length === 64 || value.length === 40) && /^[0-9a-f]+$/i.test(value);
}

function IdentityValue({ value }: { value: string }) {
  if (isDigestIdentity(value)) {
    return (
      <span className="trust-digest-cell">
        <Digest value={value} />
      </span>
    );
  }
  return (
    <code className="mono trust-opaque" title={value}>
      {value}
    </code>
  );
}

function signatureTone(status: TslSignatureStatus): 'ok' | 'error' {
  return status === 'Valid' ? 'ok' : 'error';
}

function refreshOutcomeTone(outcome: 'Success' | 'Failed'): 'ok' | 'error' {
  return outcome === 'Success' ? 'ok' : 'error';
}

function refreshOutcomeLabel(outcome: 'Success' | 'Failed'): MessageKey {
  return outcome === 'Success' ? 'trust.refresh.outcome.success' : 'trust.refresh.outcome.failed';
}

function statusTone(kind: TslServiceStatusKind): 'ok' | 'warn' | 'neutral' {
  if (kind === 'Granted') return 'ok';
  if (kind === 'Withdrawn') return 'warn';
  return 'neutral';
}

function ServiceStatusBadge({ status }: { status: TslServiceStatusKind }) {
  const t = useT();
  return <Badge tone={statusTone(status)}>{t(serviceStatusLabel(status))}</Badge>;
}

function SignatureBadge({ status }: { status: TslSignatureStatus }) {
  const t = useT();
  return <Badge tone={signatureTone(status)}>{t(signatureLabel(status))}</Badge>;
}

function tsaStatusTone(status: TsaStatusKind): 'ok' | 'warn' | 'error' {
  if (status === 'Ready') return 'ok';
  if (status === 'Unconfigured') return 'warn';
  return 'error';
}

function tsaStatusLabel(status: TsaStatusKind): MessageKey {
  if (status === 'Ready') return 'trust.tsa.statusReady';
  if (status === 'Unconfigured') return 'trust.tsa.statusUnconfigured';
  return 'trust.tsa.statusError';
}

function probeTone(status: TsaProbeStatus): 'ok' | 'warn' | 'error' {
  if (status === 'Passed') return 'ok';
  return 'error';
}

function probeLabel(status: TsaProbeStatus): MessageKey {
  if (status === 'Passed') return 'trust.tsa.probePassed';
  return 'trust.tsa.probeFailed';
}

function TsaRecordFlags({ record }: { record: TsaRecordView }) {
  const t = useT();
  return (
    <span className="trust-flags">
      <ServiceStatusBadge status={record.status.kind} />
      {record.qualified_timestamp_service ? <Badge tone="accent">QTST</Badge> : null}
      {record.trusted ? (
        <Badge tone="ok">{t('uiLiteral.trustCatalogPage.tslConfiavel')}</Badge>
      ) : (
        <Badge tone="warn">{t('trust.flag.advisory')}</Badge>
      )}
      {record.service_supply_points.length ? (
        <Badge tone="neutral">{t('trust.flag.supplyPoint')}</Badge>
      ) : null}
    </span>
  );
}

/**
 * The enclosing section's heading, so a fact table inside it can caption itself with the block it
 * belongs to instead of every call site repeating the string (t101).
 */
const TrustSectionTitle = createContext<string | null>(null);

function TrustDetailSection({
  title,
  tone,
  children,
}: {
  title: string;
  tone?: 'warn';
  children: ReactNode;
}) {
  return (
    <TrustSectionTitle.Provider value={title}>
      <section
        role="group"
        aria-label={title}
        className={`trust-detail-section${tone === 'warn' ? ' trust-detail-section--warn' : ''}`}
      >
        <h4 className="field__label trust-detail-section__title">{title}</h4>
        {children}
      </section>
    </TrustSectionTitle.Provider>
  );
}

/**
 * Read-only facts about ONE subject, as a two-column table (t101).
 *
 * The user asked for the trust list "table displayed styled so its easier to read". These blocks
 * were a `<dl>` tiled by `auto-fit, minmax(11rem, 1fr)`, so a term and its value sat in whatever
 * column the viewport happened to produce and the eye had to re-find the label/value rhythm on
 * every row — the exact complaint. A field/value pair genuinely IS tabular data, and the About
 * panel already set that precedent here (`settings.about.column.item` / `.value`), so this follows
 * it rather than inventing a shape: a real `<table>` with `<th scope="col">` above and
 * `<th scope="row">` beside every value, which is also what tells a screen reader that the left
 * cell names the right one.
 *
 * The header carries no help glyph. These two columns are "Campo" and "Valor" — there is nothing
 * to say about them that the words do not already say, and "Campo — o campo" is worse than an
 * absent tooltip. Per-column help is reserved for the multi-column grids below, where the column
 * names are domain terms.
 *
 * The caption comes from the enclosing {@link TrustDetailSection}, so each table is announced as
 * the block it belongs to ("Identificação da lista", "Configuração") rather than as an anonymous
 * grid; `Table` renders it visually hidden.
 */
function TrustFactTable({ children }: { children: ReactNode }) {
  const t = useT();
  const title = useContext(TrustSectionTitle);
  return (
    <Table
      className="trust-fact-table trust-opaque"
      caption={title ?? t('trust.table.facts.caption')}
      head={
        <tr>
          <th scope="col">{t('trust.table.field')}</th>
          <th scope="col">{t('trust.table.value')}</th>
        </tr>
      }
    >
      {children}
    </Table>
  );
}

/**
 * Repeated homogeneous entries — the three blocks on this page that genuinely are grids of the
 * same shape repeated, and so become real tables with per-column help (t101).
 *
 * These get `ColumnHead` where the fact tables above do not, because their column names are domain
 * terms an operator cannot infer: what a *status-history* row is evidence of, what distinguishes a
 * digital identity's raw value from its SHA-256, what the attributes column is asserting.
 *
 * Identifier discipline (the entity-column rule, which bites harder here because these ARE the
 * identifiers): nothing is truncated to fit. A digest renders through `Digest`, which abbreviates
 * with a focus-reachable tooltip carrying the full value and keeps the text selectable; every other
 * identifier wraps inside `.trust-opaque`, which the global selection policy already opts back into
 * text selection, so a fingerprint stays copyable.
 */
function StatusHistoryTable({ history }: { history: readonly TslServiceHistoryView[] }) {
  const t = useT();
  return (
    <Table
      className="trust-history-table trust-opaque"
      caption={t('trust.table.history.caption')}
      head={
        <tr>
          <ColumnHead
            label={t('trust.table.history.status')}
            help={t('trust.table.history.status.help')}
          />
          <ColumnHead
            label={t('trust.table.history.name')}
            help={t('trust.table.history.name.help')}
          />
          <ColumnHead
            label={t('trust.table.history.type')}
            help={t('trust.table.history.type.help')}
          />
          <ColumnHead
            label={t('trust.table.history.since')}
            help={t('trust.table.history.since.help')}
          />
        </tr>
      }
    >
      {history.map((entry, index) => (
        <tr key={`${entry.service_type}-${entry.status.kind}-${index}`}>
          <td data-label={t('trust.table.history.status')}>
            <ServiceStatusBadge status={entry.status.kind} />
          </td>
          <td data-label={t('trust.table.history.name')}>{entry.name || '—'}</td>
          <td className="mono trust-opaque" data-label={t('trust.table.history.type')}>
            {entry.service_type}
          </td>
          <td className="mono" data-label={t('trust.table.history.since')}>
            {entry.status_starting_time ?? entry.status_starting_time_raw ?? '—'}
          </td>
        </tr>
      ))}
    </Table>
  );
}

function DigitalIdentitiesTable({ identities }: { identities: readonly TslDigitalIdentityView[] }) {
  const t = useT();
  return (
    <Table
      className="trust-identity-table trust-opaque"
      caption={t('trust.table.identity.caption')}
      head={
        <tr>
          <ColumnHead
            label={t('trust.table.identity.kind')}
            help={t('trust.table.identity.kind.help')}
          />
          <ColumnHead
            label={t('trust.table.identity.value')}
            help={t('trust.table.identity.value.help')}
          />
          <ColumnHead
            label={t('trust.table.identity.digest')}
            help={t('trust.table.identity.digest.help')}
          />
        </tr>
      }
    >
      {identities.map((identity) => (
        <tr key={`${identity.kind}-${identity.value}-${identity.sha256 ?? ''}`}>
          <td className="mono" data-label={t('trust.table.identity.kind')}>
            {identity.kind}
          </td>
          <td data-label={t('trust.table.identity.value')}>
            <IdentityValue value={identity.value} />
          </td>
          <td data-label={t('trust.table.identity.digest')}>
            {/* Only when it adds something: for a digest-shaped identity the value column already
                IS the SHA-256, and repeating it would suggest two different fingerprints. */}
            {identity.sha256 && identity.sha256 !== identity.value ? (
              <IdentityValue value={identity.sha256} />
            ) : (
              <span className="muted">—</span>
            )}
          </td>
        </tr>
      ))}
    </Table>
  );
}

function ProviderServicesTable({
  services,
  onSelectService,
}: {
  services: readonly TslServiceSummaryView[];
  onSelectService: (id: string) => void;
}) {
  const t = useT();
  return (
    <Table
      className="trust-services-table trust-opaque"
      caption={t('trust.table.service.caption')}
      head={
        <tr>
          <ColumnHead
            label={t('trust.table.service.name')}
            help={t('trust.table.service.name.help')}
          />
          <ColumnHead
            label={t('trust.table.service.type')}
            help={t('trust.table.service.type.help')}
          />
          <ColumnHead
            label={t('trust.table.service.attributes')}
            help={t('trust.table.service.attributes.help')}
          />
        </tr>
      }
    >
      {services.map((service) => (
        <tr key={service.id}>
          <td data-label={t('trust.table.service.name')}>
            {/* The row's own affordance stays a real button, so the table is navigable by keyboard
                exactly as the list of rows it replaced was. */}
            <button
              type="button"
              className="trust-provider-link"
              onClick={() => onSelectService(service.id)}
            >
              {service.name}
            </button>
          </td>
          <td className="mono trust-opaque" data-label={t('trust.table.service.type')}>
            {service.service_type}
          </td>
          <td data-label={t('trust.table.service.attributes')}>
            <ServiceFlags service={service} />
          </td>
        </tr>
      ))}
    </Table>
  );
}

function TrustControlPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="trust-control-panel">
      <p className="trust-control-panel__title">{title}</p>
      {children}
    </section>
  );
}

function TrustResultGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="trust-result-group" role="group" aria-label={title}>
      <p className="trust-result-group__title">{title}</p>
      {children}
    </section>
  );
}

function TsaAcceptedHash({ digest }: { digest: string }) {
  const t = useT();
  return (
    <span
      className="trust-accepted-hash"
      role="group"
      aria-label={t('trust.tsa.acceptedHash.aria', { digest })}
    >
      <Digest value={digest} />
    </span>
  );
}

function tsaRecordMatches(record: TsaRecordView, term: string): boolean {
  return includesTerm(
    [
      record.provider_name,
      record.name,
      record.service_type,
      record.status.kind,
      record.status.uri,
      record.status_starting_time_raw,
      ...record.additional_service_info,
      ...record.service_supply_points,
      ...record.identities.subject_names,
      ...record.identities.subject_key_ids,
      record.analysis.classification,
      record.analysis.trust_basis,
      ...record.analysis.blocking_reasons,
    ],
    term,
  );
}

function tsaRecordMatchesStructuredFilters(
  record: TsaRecordView,
  typeFilter: TsaTypeFilter,
  statusFilter: TrustStatusFilter,
  supplyOnly: boolean,
): boolean {
  const serviceType = normalize(record.service_type);
  const typeMatches =
    typeFilter === 'all' ||
    (typeFilter === 'qtst' && record.qualified_timestamp_service) ||
    (typeFilter === 'tst' && serviceType.includes('/tsa/tst'));
  const statusMatches = statusFilter === 'all' || record.status.kind === statusFilter;
  return typeMatches && statusMatches && (!supplyOnly || record.service_supply_points.length > 0);
}

function TsaRecordDetail({ record }: { record: TsaRecordView }) {
  const t = useT();
  return (
    <div className="trust-detail stack--tight">
      <div className="trust-detail__head">
        <TsaRecordFlags record={record} />
        <h3 className="trust-detail__title">{record.name}</h3>
      </div>
      <p className="muted trust-source-note" title={record.provider_name}>
        {record.provider_name}
      </p>
      <IdentifierMatchNote fields={record.identifier_match} />

      <TrustDetailSection title={t('trust.detail.summary')}>
        <TrustFactTable>
          <tr>
            <th scope="row">{t('trust.service.type')}</th>
            <td className="mono trust-opaque" title={record.service_type}>
              {record.service_type}
            </td>
          </tr>
          <tr>
            <th scope="row">{t('trust.service.statusStartingTime')}</th>
            <td className="mono">
              {record.status_starting_time ?? record.status_starting_time_raw ?? '—'}
            </td>
          </tr>
          <tr>
            <th scope="row">{t('trust.tsa.detail.grantedEffective')}</th>
            <td>
              {record.granted ? t('common.yes') : t('common.no')} /{' '}
              {record.effective ? t('common.yes') : t('common.no')}
            </td>
          </tr>
          <tr>
            <th scope="row">{t('trust.service.certificates')}</th>
            <td className="mono">{record.identities.certificates}</td>
          </tr>
        </TrustFactTable>
      </TrustDetailSection>

      <TrustDetailSection title={t('trust.detail.supplyPoints')}>
        {record.service_supply_points.length ? (
          <ul className="trust-detail-list">
            {record.service_supply_points.map((point) => (
              <li key={point} className="mono trust-opaque" title={point}>
                {point}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">{t('trust.detail.none')}</p>
        )}
      </TrustDetailSection>

      <TrustDetailSection title={t('trust.detail.history')}>
        <TrustFactTable>
          <tr>
            <th scope="row">{t('trust.detail.historyEntries')}</th>
            <td className="mono">{record.history_count}</td>
          </tr>
          <tr>
            <th scope="row">{t('trust.tsa.detail.classification')}</th>
            <td>{record.analysis.classification}</td>
          </tr>
          <tr>
            <th scope="row">{t('trust.tsa.detail.trustBasis')}</th>
            <td>{record.analysis.trust_basis}</td>
          </tr>
        </TrustFactTable>
      </TrustDetailSection>

      {record.analysis.blocking_reasons.length ? (
        <TrustDetailSection title={t('trust.tsa.detail.blockingReasons')} tone="warn">
          <ul className="trust-detail-list">
            {record.analysis.blocking_reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </TrustDetailSection>
      ) : null}

      <TrustDetailSection title={t('trust.detail.identities')}>
        <div className="trust-detail-subsection">
          <p className="field__label">{t('trust.service.subjectNames')}</p>
          {record.identities.subject_names.length ? (
            <ul className="trust-detail-list">
              {record.identities.subject_names.map((name) => (
                <li key={name} title={name}>
                  {name}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">{t('trust.detail.none')}</p>
          )}
        </div>
        <div className="trust-detail-subsection">
          <p className="field__label">{t('trust.tsa.detail.ski')}</p>
          {record.identities.subject_key_ids.length ? (
            <ul className="trust-detail-list">
              {record.identities.subject_key_ids.map((ski) => (
                <li key={ski}>
                  <IdentityValue value={ski} />
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">{t('trust.detail.none')}</p>
          )}
        </div>
      </TrustDetailSection>
    </div>
  );
}

function TsaToolingPanel() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const tsa = useTsaCatalog();
  const term = params.get('tsaQ') ?? '';
  const identifier = params.get('tsaIdentifier') ?? '';
  const normalizedTerm = normalize(term.trim());
  const selectedId = params.get('tsaRecord') ?? '';
  const typeFilter = optionValue(params.get('tsaType'), TSA_TYPE_FILTERS, 'all');
  const statusFilter = optionValue(params.get('tsaStatus'), TRUST_STATUS_FILTERS, 'all');
  const supplyOnly = params.get('tsaSupply') === '1';
  const tsaSearchParams = useMemo<TsaCatalogSearchParams>(
    () => ({
      search: term,
      identifier,
      service_type: tsaServiceTypeParam(typeFilter),
      status: statusFilter === 'all' ? undefined : statusFilter,
      supply_point: supplyOnly ? 'any' : undefined,
      limit: TRUST_SEARCH_LIMIT,
    }),
    [identifier, statusFilter, supplyOnly, term, typeFilter],
  );
  const tsaSearchEnabled = hasStructuredSearchParams(tsaSearchParams);
  const tsaSearch = useTsaCatalogSearch(tsaSearchParams, tsaSearchEnabled);
  const tsaSearchPending = tsaSearchEnabled && tsaSearch.isPending;

  const records = useMemo(() => {
    if (tsaSearchEnabled) return tsaSearch.data ?? [];
    const all = tsa.data?.records ?? [];
    return all.filter(
      (record) =>
        tsaRecordMatches(record, normalizedTerm) &&
        tsaRecordMatchesStructuredFilters(record, typeFilter, statusFilter, supplyOnly),
    );
  }, [
    normalizedTerm,
    statusFilter,
    supplyOnly,
    tsa.data,
    tsaSearch.data,
    tsaSearchEnabled,
    typeFilter,
  ]);

  const selected =
    records.find((record) => record.id === selectedId) ??
    tsa.data?.records.find((record) => record.id === selectedId) ??
    records[0] ??
    null;

  function setParam(name: string, value: string | null, replace = true) {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (value === null || value === '') p.delete(name);
        else p.set(name, value);
        return p;
      },
      { replace },
    );
  }

  function setBooleanParam(name: string, value: boolean) {
    setParam(name, value ? '1' : null);
  }

  return (
    <Card title={t('trust.tsa.title')}>
      {tsa.isLoading ? (
        <SkeletonDeflist rows={8} />
      ) : tsa.error ? (
        <ErrorNote error={tsa.error} />
      ) : tsa.data ? (
        <div className="trust-tsa">
          <div
            className="trust-statusline trust-statusline--featured"
            role="group"
            aria-label={t('trust.tsa.summary.aria')}
          >
            <div className="trust-statusline__item trust-statusline__item--wide">
              <span className="trust-statusline__label">{t('trust.tsa.configuredUrl')}</span>
              <span className="mono trust-opaque">{tsa.data.summary.configured_url ?? '—'}</span>
            </div>
            <div className="trust-statusline__item">
              <span className="trust-statusline__label">{t('trust.tsa.status')}</span>
              <Badge tone={tsaStatusTone(tsa.data.summary.status)}>
                {t(tsaStatusLabel(tsa.data.summary.status))}
              </Badge>
            </div>
            <div className="trust-statusline__item">
              <span className="trust-statusline__label">{t('trust.tsa.fixture')}</span>
              <Badge tone={probeTone(tsa.data.summary.last_probe.status)}>
                {t(probeLabel(tsa.data.summary.last_probe.status))}
              </Badge>
            </div>
            <div className="trust-statusline__item">
              <span className="trust-statusline__label">{t('trust.tsa.trustedRecords')}</span>
              <span className="mono">
                {tsa.data.summary.trusted_records} / {tsa.data.summary.records}
              </span>
            </div>
          </div>

          <div className="trust-diagnostics-grid">
            <TrustDetailSection title={t('trust.tsa.configuration')}>
              <TrustFactTable>
                <tr>
                  <th scope="row">{t('trust.tsa.configuredUrl')}</th>
                  <td className="mono">{tsa.data.summary.configured_url ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.tsa.status')}</th>
                  <td>
                    <Badge tone={tsaStatusTone(tsa.data.summary.status)}>
                      {t(tsaStatusLabel(tsa.data.summary.status))}
                    </Badge>
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.tsa.profile')}</th>
                  <td>
                    {tsa.data.summary.profile.protocol} · {tsa.data.summary.profile.hash_algorithm}
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.tsa.acceptedHash')}</th>
                  <td className="trust-digest-cell">
                    <TsaAcceptedHash digest={tsa.data.summary.accepted_hash.digest} />
                  </td>
                </tr>
              </TrustFactTable>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.tsa.fixtureProof')}>
              <TrustFactTable>
                <tr>
                  <th scope="row">{t('trust.tsa.fixture')}</th>
                  <td>
                    <Badge tone={probeTone(tsa.data.summary.last_probe.status)}>
                      {t(probeLabel(tsa.data.summary.last_probe.status))}
                    </Badge>
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.checkedAt')}</th>
                  {/* A probe is a record of something having happened: evidentiary. */}
                  <td>
                    <DateTime
                      className="mono"
                      value={tsa.data.summary.last_probe.checked_at}
                      evidentiary
                    />
                  </td>
                </tr>
              </TrustFactTable>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.tsa.timestampToken')}>
              <TrustFactTable>
                <tr>
                  <th scope="row">GenTime</th>
                  <td className="mono">{tsa.data.summary.timestamp?.gen_time ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.tsa.policySerial')}</th>
                  <td className="mono">
                    {tsa.data.summary.timestamp
                      ? `${tsa.data.summary.timestamp.policy} / ${tsa.data.summary.timestamp.serial_number}`
                      : '—'}
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.tsa.policyAnalysis')}</th>
                  <td>
                    {tsa.data.summary.policy_analysis.fixture_policy ?? '—'} ·{' '}
                    {tsa.data.summary.policy_analysis.advisory
                      ? t('trust.tsa.policyAdvisory')
                      : t('trust.tsa.policyTrusted')}
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.tsa.token')}</th>
                  <td className="mono">
                    {t('trust.tsa.tokenBytes', {
                      bytes: tsa.data.summary.timestamp?.token_bytes ?? '—',
                    })}
                  </td>
                </tr>
              </TrustFactTable>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.tsa.tslRecords')}>
              <TrustFactTable>
                <tr>
                  <th scope="row">{t('trust.tsa.totalTrusted')}</th>
                  <td className="mono">
                    {t('trust.tsa.totalTrusted.value', {
                      total: tsa.data.summary.records,
                      trusted: tsa.data.summary.trusted_records,
                    })}
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.tsa.granted')}</th>
                  <td className="mono">{tsa.data.summary.granted_records}</td>
                </tr>
              </TrustFactTable>
            </TrustDetailSection>
          </div>

          <div className="trust-notes">
            <p className="muted trust-source-note">{tsa.data.summary.status_message}</p>
            {tsa.data.summary.last_probe.error ? (
              <p className="muted trust-source-note">{tsa.data.summary.last_probe.error}</p>
            ) : null}
          </div>

          <div className="trust-explorer trust-explorer--tsa">
            <div className="trust-explorer__nav">
              <TrustControlPanel title={t('trust.tsa.search.title')}>
                <div className="trust-searchbox">
                  <Icon.Search />
                  <Input
                    type="search"
                    value={term}
                    onChange={(e) => setParam('tsaQ', e.target.value)}
                    placeholder={t('trust.tsa.search.placeholder')}
                    aria-label={t('trust.tsa.search.aria')}
                    autoComplete="off"
                  />
                </div>
                <Field
                  label={t('trust.identifier.label')}
                  htmlFor="tsa-identifier-filter"
                  hint={t('trust.identifier.hint')}
                  help={t('trust.identifier.help')}
                >
                  <div className="trust-searchbox">
                    <Icon.Search />
                    <Input
                      id="tsa-identifier-filter"
                      type="search"
                      value={identifier}
                      onChange={(e) => setParam('tsaIdentifier', e.target.value)}
                      placeholder={t('trust.identifier.placeholder')}
                      aria-label={t('trust.tsa.identifier.aria')}
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </div>
                </Field>
              </TrustControlPanel>
              <div
                className="trust-filter-controls"
                role="group"
                aria-label={t('trust.tsa.filters.aria')}
              >
                <Field label={t('trust.filter.type')} htmlFor="tsa-type-filter">
                  <Select
                    id="tsa-type-filter"
                    value={typeFilter}
                    options={localizedOptions(TSA_TYPE_FILTERS, t)}
                    onChange={(e) =>
                      setParam('tsaType', e.target.value === 'all' ? null : e.target.value)
                    }
                  />
                </Field>
                <Field label={t('trust.filter.status')} htmlFor="tsa-status-filter">
                  <Select
                    id="tsa-status-filter"
                    value={statusFilter}
                    options={localizedOptions(TRUST_STATUS_FILTERS, t)}
                    onChange={(e) =>
                      setParam('tsaStatus', e.target.value === 'all' ? null : e.target.value)
                    }
                  />
                </Field>
                <Toggle
                  label={t('trust.filter.withSupplyPoint')}
                  checked={supplyOnly}
                  onChange={(checked) => setBooleanParam('tsaSupply', checked)}
                />
              </div>
              {tsaSearchPending ? (
                <TrustResultsSkeleton label={t('trust.tsa.search.loading')} />
              ) : tsaSearchEnabled && tsaSearch.error ? (
                <ErrorNote error={tsaSearch.error} />
              ) : (
                <div className="trust-results" aria-live="polite">
                  <p className="trust-results__count muted">
                    {t('trust.tsa.search.count', {
                      shown: records.length,
                      total: tsa.data.records.length,
                    })}
                  </p>
                  {records.length ? (
                    <TrustResultGroup title={t('trust.tsa.results.aria')}>
                      <ul className="trust-picklist" aria-label={t('trust.tsa.results.aria')}>
                        {records.map((record) => (
                          <li key={record.id}>
                            <button
                              type="button"
                              className={
                                selected?.id === record.id
                                  ? 'trust-pick trust-pick--service is-current'
                                  : 'trust-pick trust-pick--service'
                              }
                              onClick={() => setParam('tsaRecord', record.id, false)}
                            >
                              <span className="trust-pick__head">
                                <code
                                  className="mono trust-pick__code"
                                  title={record.provider_name}
                                >
                                  {record.provider_name}
                                </code>
                                <span
                                  className="trust-pick__meta muted"
                                  title={record.service_type}
                                >
                                  {record.service_type}
                                </span>
                              </span>
                              <span className="trust-pick__name" title={record.name}>
                                {record.name}
                              </span>
                              <TsaRecordFlags record={record} />
                              <IdentifierMatchNote fields={record.identifier_match} />
                            </button>
                          </li>
                        ))}
                      </ul>
                    </TrustResultGroup>
                  ) : (
                    <EmptyState title={t('trust.tsa.empty.title')}>
                      <p>{t('trust.tsa.empty.body', { term: identifier.trim() || term.trim() })}</p>
                    </EmptyState>
                  )}
                </div>
              )}
            </div>
            <div className="trust-explorer__detail">
              {selected ? (
                <TsaRecordDetail record={selected} />
              ) : (
                <EmptyState title={t('trust.tsa.detail.empty.title')}>
                  <p>{t('trust.tsa.detail.empty.body')}</p>
                </EmptyState>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </Card>
  );
}

function TrustStatusPanel() {
  const t = useT();
  const status = useTrustStatus();
  const refresh = useRefreshTrustTsl();

  return (
    <Card title={t('trust.status.title')}>
      {status.isLoading ? (
        <SkeletonDeflist rows={6} />
      ) : status.error ? (
        <ErrorNote error={status.error} />
      ) : status.data ? (
        <div className="stack--tight">
          <div className="trust-toolbar">
            <div>
              <p className="trust-toolbar__title">{t('trust.refresh.title')}</p>
              <p className="muted trust-source-note">{t('trust.refresh.body')}</p>
            </div>
            <Button
              type="button"
              icon={<Icon.Refresh />}
              onClick={() => refresh.mutate({})}
              disabled={refresh.isPending}
            >
              {refresh.isPending ? t('trust.refresh.pending') : t('trust.refresh.action')}
            </Button>
          </div>
          {refresh.error ? <ErrorNote error={refresh.error} /> : null}

          <div
            className="trust-statusline"
            role="group"
            aria-label={t('trust.status.summary.aria')}
          >
            <div className="trust-statusline__item">
              <span className="trust-statusline__label">{t('trust.status.source')}</span>
              <Badge tone={status.data.source.kind === 'Cache' ? 'accent' : 'neutral'}>
                {t(sourceLabel(status.data.source.kind))}
              </Badge>
            </div>
            <div className="trust-statusline__item">
              <span className="trust-statusline__label">{t('trust.status.signature')}</span>
              <SignatureBadge status={status.data.validation.signature} />
            </div>
            <div className="trust-statusline__item">
              <span className="trust-statusline__label">{t('trust.status.freshness')}</span>
              <Badge tone={status.data.stale ? 'warn' : 'ok'}>
                {status.data.stale ? t('trust.status.stale') : t('trust.status.current')}
              </Badge>
            </div>
            <div className="trust-statusline__item trust-statusline__item--wide">
              <span className="trust-statusline__label">{t('trust.status.checkedAt')}</span>
              {/* When the trust list was last validated — an evidentiary check time. */}
              <DateTime className="mono" value={status.data.validation.checked_at} evidentiary />
            </div>
          </div>

          {status.data.last_refresh ? (
            <TrustDetailSection title={t('trust.refresh.lastAttempt')}>
              <TrustFactTable>
                <tr>
                  <th scope="row">{t('trust.refresh.result')}</th>
                  <td>
                    <Badge tone={refreshOutcomeTone(status.data.last_refresh.outcome)}>
                      {t(refreshOutcomeLabel(status.data.last_refresh.outcome))}
                    </Badge>
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.refresh.attemptedAt')}</th>
                  <td>
                    <DateTime
                      className="mono"
                      value={status.data.last_refresh.attempted_at}
                      evidentiary
                    />
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.source')}</th>
                  <td className="mono trust-opaque">
                    {status.data.last_refresh.source_url ??
                      status.data.last_refresh.source_path ??
                      '—'}
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.refresh.records')}</th>
                  <td className="mono">
                    {t('trust.search.count', {
                      providers: status.data.last_refresh.providers ?? '—',
                      services: status.data.last_refresh.services ?? '—',
                    })}
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.refresh.importSignature')}</th>
                  <td>
                    <SignatureBadge status={status.data.last_refresh.validation.signature} />
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.trusted')}</th>
                  <td className="mono">
                    {status.data.last_refresh.trusted_esignature_services ?? '—'}
                  </td>
                </tr>
              </TrustFactTable>
              {status.data.last_refresh.error ? (
                <p className="muted trust-source-note">{status.data.last_refresh.error}</p>
              ) : status.data.last_refresh.validation.error ? (
                <p className="muted trust-source-note">
                  {status.data.last_refresh.validation.error}
                </p>
              ) : null}
            </TrustDetailSection>
          ) : null}

          <div className="trust-diagnostics-grid">
            <TrustDetailSection title={t('trust.status.listIdentification')}>
              <TrustFactTable>
                <tr>
                  <th scope="row">{t('trust.status.scheme')}</th>
                  <td>{status.data.scheme_name}</td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.operator')}</th>
                  <td>{status.data.scheme_operator_name}</td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.territory')}</th>
                  <td className="mono">{status.data.scheme_territory}</td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.sequence')}</th>
                  <td className="mono">{status.data.sequence_number ?? '—'}</td>
                </tr>
              </TrustFactTable>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.status.dates')}>
              <TrustFactTable>
                <tr>
                  <th scope="row">{t('trust.status.issueDate')}</th>
                  {/* When the scheme operator issued this list — evidentiary. */}
                  <td>
                    <DateTime className="mono" value={status.data.issue_date_time} evidentiary />
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.nextUpdate')}</th>
                  {/* A scheduled future update, not a record of an event. */}
                  <td>
                    <DateTime className="mono" value={status.data.next_update} />
                  </td>
                </tr>
              </TrustFactTable>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.status.coverage')}>
              <TrustFactTable>
                <tr>
                  <th scope="row">{t('trust.status.providers')}</th>
                  <td className="mono">{status.data.providers}</td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.services')}</th>
                  <td className="mono">{status.data.services}</td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.qualified')}</th>
                  <td className="mono">{status.data.qualified_esignature_services}</td>
                </tr>
                <tr>
                  <th scope="row">{t('trust.status.trusted')}</th>
                  <td className="mono">{status.data.trusted_esignature_services}</td>
                </tr>
              </TrustFactTable>
            </TrustDetailSection>
          </div>

          {status.data.source.note ? (
            <p className="muted trust-source-note">{status.data.source.note}</p>
          ) : null}
          {status.data.validation.error ? (
            <p className="muted trust-source-note">{status.data.validation.error}</p>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}

function providerMatches(provider: TslProviderView, term: string): boolean {
  return (
    includesTerm([provider.name, ...provider.trade_names, ...provider.information_uris], term) ||
    provider.services.some((service) => serviceMatches(service, term))
  );
}

function serviceMatches(service: TslServiceSummaryView, term: string): boolean {
  return includesTerm(
    [
      service.name,
      service.provider_name,
      service.service_type,
      service.status.kind,
      service.status.uri,
      service.status_starting_time_raw,
      ...service.additional_service_info,
      ...service.service_supply_points,
      ...service.identities.subject_names,
      ...service.identities.subject_key_ids,
    ],
    term,
  );
}

function serviceMatchesFilter(service: TslServiceSummaryView, filter: TrustFilter): boolean {
  if (filter === 'qualified') return service.qualified_for_esignatures;
  if (filter === 'trusted') return service.trusted_for_esignatures;
  if (filter === 'caqc') return service.ca_qc;
  return true;
}

function serviceMatchesType(service: TslServiceSummaryView, filter: TrustTypeFilter): boolean {
  const serviceType = normalize(service.service_type);
  if (filter === 'caqc') return service.ca_qc || serviceType.includes('/ca/qc');
  if (filter === 'tsa') return serviceType.includes('/tsa');
  if (filter === 'qtst') return serviceType.includes('/tsa/qtst');
  if (filter === 'other') return !service.ca_qc && !serviceType.includes('/tsa');
  return true;
}

function serviceMatchesStatus(service: TslServiceSummaryView, filter: TrustStatusFilter): boolean {
  return filter === 'all' || service.status.kind === filter;
}

function serviceMatchesStructuredFilters(
  service: TslServiceSummaryView,
  typeFilter: TrustTypeFilter,
  statusFilter: TrustStatusFilter,
  historyOnly: boolean,
  supplyOnly: boolean,
): boolean {
  return (
    serviceMatchesType(service, typeFilter) &&
    serviceMatchesStatus(service, statusFilter) &&
    (!historyOnly || service.history_count > 0) &&
    (!supplyOnly || service.service_supply_points.length > 0)
  );
}

function flattenServices(catalog: TslCatalogView): TslServiceSummaryView[] {
  return catalog.providers.flatMap((provider) => provider.services);
}

function TrustFilterPills({
  active,
  onSelect,
}: {
  active: TrustFilter;
  onSelect: (filter: TrustFilter) => void;
}) {
  const t = useT();
  return (
    <div className="trust-filter-pills" role="group" aria-label={t('trust.filter.aria')}>
      {TRUST_FILTERS.map((filter) => (
        <button
          key={filter}
          type="button"
          className={filter === active ? 'trust-filter is-active' : 'trust-filter'}
          aria-pressed={filter === active}
          onClick={() => onSelect(filter)}
        >
          {t(filterLabel(filter))}
        </button>
      ))}
    </div>
  );
}

function ProviderPick({
  provider,
  selected,
  onSelect,
}: {
  provider: TslProviderView;
  selected: boolean;
  onSelect: () => void;
}) {
  const t = useT();
  const granted = provider.services.filter((s) => s.status.kind === 'Granted').length;
  return (
    <button
      type="button"
      className={
        selected ? 'trust-pick trust-pick--provider is-current' : 'trust-pick trust-pick--provider'
      }
      onClick={onSelect}
    >
      <span className="trust-pick__head">
        <span className="trust-pick__kind">{t('trust.provider.kind')}</span>
        <span className="trust-pick__meta muted">
          {t('trust.provider.serviceCount', { count: provider.services.length })}
        </span>
      </span>
      <span className="trust-pick__name">{provider.name}</span>
      <span className="trust-pick__meta muted">
        {t('trust.provider.grantedCount', { count: granted })}
      </span>
    </button>
  );
}

function ServiceFlags({ service }: { service: TslServiceSummaryView }) {
  const t = useT();
  return (
    <span className="trust-flags">
      <ServiceStatusBadge status={service.status.kind} />
      {service.ca_qc ? <Badge tone="accent">{t('trust.flag.caqc')}</Badge> : null}
      {service.qualified_for_esignatures ? (
        <Badge tone="ok">{t('trust.flag.qualified')}</Badge>
      ) : null}
      {service.trusted_for_esignatures ? <Badge tone="ok">{t('trust.flag.trusted')}</Badge> : null}
      {service.history_count > 0 ? <Badge tone="neutral">{t('trust.flag.history')}</Badge> : null}
      {service.service_supply_points.length ? (
        <Badge tone="neutral">{t('trust.flag.supplyPoint')}</Badge>
      ) : null}
    </span>
  );
}

function ServicePick({
  service,
  selected,
  onSelect,
}: {
  service: TslServiceSummaryView;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      className={
        selected ? 'trust-pick trust-pick--service is-current' : 'trust-pick trust-pick--service'
      }
      onClick={onSelect}
    >
      <span className="trust-pick__head">
        <code className="mono trust-pick__code" title={service.provider_name}>
          {service.provider_name}
        </code>
        <span className="trust-pick__meta muted" title={service.service_type}>
          {service.service_type}
        </span>
      </span>
      <span className="trust-pick__name" title={service.name}>
        {service.name}
      </span>
      <ServiceFlags service={service} />
      <IdentifierMatchNote fields={service.identifier_match} />
    </button>
  );
}

/**
 * The two shapes this page waits on. A trust detail is a heading over label/value pairs;
 * a search is a `.trust-results` column of pick rows. Both are known before the query
 * lands, so both reserve their real box rather than showing a line of text.
 */
function TrustDetailSkeleton({ label }: { label: string }) {
  return (
    <SkeletonRegion className="trust-detail stack--tight" label={label}>
      <Skeleton height="1.5rem" width="55%" />
      <SkeletonDeflist rows={6} />
    </SkeletonRegion>
  );
}

function TrustResultsSkeleton({ label, rows = 6 }: { label: string; rows?: number }) {
  return (
    <SkeletonRegion className="trust-results" label={label}>
      <Skeleton height="0.85rem" width="12rem" />
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} height="2.8rem" />
      ))}
    </SkeletonRegion>
  );
}

function ProviderDetail({
  id,
  onSelectService,
}: {
  id: string;
  onSelectService: (id: string) => void;
}) {
  const t = useT();
  const detail = useTrustProvider(id);

  if (detail.isLoading) return <TrustDetailSkeleton label={t('trust.detail.loading')} />;
  if (detail.error) return <ErrorNote error={detail.error} />;
  if (!detail.data) return null;

  const provider = detail.data.provider;
  return (
    <div className="trust-detail stack--tight">
      <div className="trust-detail__head">
        <Badge tone="accent">{t('trust.provider.kind')}</Badge>
        <h3 className="trust-detail__title">{provider.name}</h3>
      </div>
      <TrustDetailSection title={t('trust.detail.summary')}>
        <TrustFactTable>
          <tr>
            <th scope="row">{t('trust.provider.tradeNames')}</th>
            <td>{provider.trade_names.length ? provider.trade_names.join(', ') : '—'}</td>
          </tr>
          <tr>
            <th scope="row">{t('trust.provider.informationUris')}</th>
            <td>{provider.information_uris.length ? provider.information_uris.join(', ') : '—'}</td>
          </tr>
          <tr>
            <th scope="row">{t('trust.status.services')}</th>
            <td className="mono">{provider.services.length}</td>
          </tr>
          <tr>
            <th scope="row">{t('trust.provider.analysis')}</th>
            <td>
              {t('trust.provider.analysis.value', {
                granted: provider.analysis.granted_services,
                history: provider.analysis.services_with_history,
                supply: provider.analysis.services_with_supply_points,
              })}
            </td>
          </tr>
        </TrustFactTable>
      </TrustDetailSection>

      {provider.analysis.duplicate_service_names.length ? (
        <TrustDetailSection title={t('trust.provider.duplicateNames')}>
          <ul className="trust-detail-list">
            {provider.analysis.duplicate_service_names.map((name) => (
              <li key={name}>{name}</li>
            ))}
          </ul>
        </TrustDetailSection>
      ) : null}

      <TrustDetailSection title={t('trust.provider.services')}>
        <ProviderServicesTable services={provider.services} onSelectService={onSelectService} />
      </TrustDetailSection>
    </div>
  );
}

function ServiceDetail({
  id,
  onSelectProvider,
  identifierMatch,
}: {
  id: string;
  onSelectProvider: (id: string) => void;
  identifierMatch?: TrustIdentifierMatchField[];
}) {
  const t = useT();
  const detail = useTrustService(id);

  if (detail.isLoading) return <TrustDetailSkeleton label={t('trust.detail.loading')} />;
  if (detail.error) return <ErrorNote error={detail.error} />;
  if (!detail.data) return null;

  const service = detail.data;
  const matchFields = service.identifier_match ?? identifierMatch;
  return (
    <div className="trust-detail stack--tight">
      <div className="trust-detail__head">
        <ServiceStatusBadge status={service.status.kind} />
        <h3 className="trust-detail__title" title={service.name}>
          {service.name}
        </h3>
      </div>
      <button
        type="button"
        className="trust-provider-link"
        onClick={() => onSelectProvider(service.provider_id)}
        title={service.provider_name}
      >
        {service.provider_name}
      </button>
      <ServiceFlags service={service} />
      <IdentifierMatchNote fields={matchFields} />

      <TrustDetailSection title={t('trust.detail.summary')}>
        <TrustFactTable>
          <tr>
            <th scope="row">{t('trust.service.type')}</th>
            <td className="mono trust-opaque" title={service.service_type}>
              {service.service_type}
            </td>
          </tr>
          <tr>
            <th scope="row">{t('trust.service.statusUri')}</th>
            <td className="mono">{service.status.uri ?? '—'}</td>
          </tr>
          <tr>
            <th scope="row">{t('trust.service.statusStartingTime')}</th>
            <td className="mono">
              {service.status_starting_time ?? service.status_starting_time_raw ?? '—'}
            </td>
          </tr>
          <tr>
            <th scope="row">{t('trust.service.certificates')}</th>
            <td className="mono">{service.identities.certificates}</td>
          </tr>
        </TrustFactTable>
      </TrustDetailSection>

      {service.additional_service_info.length ? (
        <TrustDetailSection title={t('trust.service.additionalInfo')}>
          <ul className="trust-detail-list">
            {service.additional_service_info.map((info) => (
              <li key={info}>{info}</li>
            ))}
          </ul>
        </TrustDetailSection>
      ) : null}

      <TrustDetailSection title={t('trust.detail.supplyPoints')}>
        {service.service_supply_points.length ? (
          <ul className="trust-detail-list">
            {service.service_supply_points.map((point) => (
              <li key={point} className="mono trust-opaque" title={point}>
                {point}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">{t('trust.detail.none')}</p>
        )}
      </TrustDetailSection>

      <TrustDetailSection title={t('trust.detail.history')}>
        {/* The count was a one-row fact table, which is a table pretending to be a sentence. It is
            a sentence, and the history itself — repeated homogeneous entries — is the table. */}
        <p className="muted">{t('trust.detail.historyCount', { count: service.history_count })}</p>
        {service.history.length ? (
          <StatusHistoryTable history={service.history} />
        ) : (
          <p className="muted">{t('trust.detail.noStatusHistory')}</p>
        )}
      </TrustDetailSection>

      <TrustDetailSection title={t('trust.detail.identities')}>
        <div className="trust-detail-subsection">
          <p className="field__label">{t('trust.service.subjectNames')}</p>
          {service.identities.subject_names.length ? (
            <ul className="trust-detail-list">
              {service.identities.subject_names.map((name) => (
                <li key={name} title={name}>
                  {name}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">{t('trust.detail.none')}</p>
          )}
        </div>
        <div className="trust-detail-subsection">
          <p className="field__label">{t('trust.service.digitalIdentities')}</p>
          {service.digital_identities.length ? (
            <DigitalIdentitiesTable identities={service.digital_identities.slice(0, 8)} />
          ) : (
            <p className="muted">{t('trust.detail.none')}</p>
          )}
        </div>
      </TrustDetailSection>
    </div>
  );
}

function TrustCatalogExplorer() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const catalog = useTrustCatalog();
  const term = params.get('trustQ') ?? '';
  const identifier = params.get('trustIdentifier') ?? '';
  const normalizedTerm = normalize(term.trim());
  const filterParam = params.get('trustFilter') as TrustFilter | null;
  const filter: TrustFilter =
    filterParam && TRUST_FILTERS.includes(filterParam) ? filterParam : 'all';
  const typeFilter = optionValue(params.get('trustType'), TRUST_TYPE_FILTERS, 'all');
  const statusFilter = optionValue(params.get('trustStatus'), TRUST_STATUS_FILTERS, 'all');
  const historyOnly = params.get('trustHistory') === '1';
  const supplyOnly = params.get('trustSupply') === '1';
  const selectedProvider = params.get('trustProvider') ?? '';
  const selectedService = params.get('trustService') ?? '';
  const trustSearchParams = useMemo<TslCatalogSearchParams>(
    () => ({
      search: term,
      identifier,
      service_type: trustServiceTypeParam(typeFilter, filter),
      status: statusFilter === 'all' ? undefined : statusFilter,
      history: historyOnly ? 'any' : undefined,
      supply_point: supplyOnly ? 'any' : undefined,
      limit: TRUST_SEARCH_LIMIT,
    }),
    [filter, historyOnly, identifier, statusFilter, supplyOnly, term, typeFilter],
  );
  const identifierActive = !!identifier.trim();
  const trustSearchEnabled =
    (filter !== 'providers' || identifierActive) && hasStructuredSearchParams(trustSearchParams);
  const trustSearch = useTrustCatalogSearch(trustSearchParams, trustSearchEnabled);
  const trustSearchPending = trustSearchEnabled && trustSearch.isPending;

  const results = useMemo(() => {
    const data = catalog.data;
    if (!data)
      return { providers: [] as TslProviderView[], services: [] as TslServiceSummaryView[] };
    const matchesStructured = (service: TslServiceSummaryView) =>
      serviceMatchesStructuredFilters(service, typeFilter, statusFilter, historyOnly, supplyOnly);
    const serviceCandidates = trustSearchEnabled ? (trustSearch.data ?? []) : flattenServices(data);
    const providers = (() => {
      if (filter !== 'all' && filter !== 'providers') return [];
      if (identifierActive && trustSearchEnabled) {
        const providerIds = new Set(serviceCandidates.map((service) => service.provider_id));
        return data.providers.filter((provider) => providerIds.has(provider.id));
      }
      return data.providers.filter(
        (provider) =>
          providerMatches(provider, normalizedTerm) &&
          provider.services.some((service) => matchesStructured(service)),
      );
    })();
    const services =
      filter !== 'providers'
        ? serviceCandidates.filter((service) => {
            if (!serviceMatchesFilter(service, filter)) return false;
            if (trustSearchEnabled) {
              return typeFilter === 'other' ? serviceMatchesType(service, typeFilter) : true;
            }
            return serviceMatches(service, normalizedTerm) && matchesStructured(service);
          })
        : [];
    return { providers, services };
  }, [
    catalog.data,
    filter,
    historyOnly,
    identifierActive,
    normalizedTerm,
    statusFilter,
    supplyOnly,
    trustSearch.data,
    trustSearchEnabled,
    typeFilter,
  ]);
  const selectedServiceIdentifierMatch = trustSearch.data?.find(
    (service) => service.id === selectedService,
  )?.identifier_match;

  function setParam(name: string, value: string | null, replace = true) {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (value === null || value === '') p.delete(name);
        else p.set(name, value);
        return p;
      },
      { replace },
    );
  }

  function selectFilter(next: TrustFilter) {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (next === 'all') p.delete('trustFilter');
        else p.set('trustFilter', next);
        return p;
      },
      { replace: true },
    );
  }

  function setBooleanParam(name: string, value: boolean) {
    setParam(name, value ? '1' : null);
  }

  function selectProvider(id: string) {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      p.set('trustProvider', id);
      p.delete('trustService');
      return p;
    });
  }

  function selectService(id: string) {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      p.set('trustService', id);
      p.delete('trustProvider');
      return p;
    });
  }

  return (
    <Card title={t('trust.explorer.title')}>
      <div className="trust-explorer">
        <div className="trust-explorer__nav">
          <div className="trust-searchbox">
            <Icon.Search />
            <Input
              type="search"
              value={term}
              onChange={(e) => setParam('trustQ', e.target.value)}
              placeholder={t('trust.search.placeholder')}
              aria-label={t('trust.search.aria')}
              autoComplete="off"
            />
          </div>
          <Field
            label={t('trust.identifier.label')}
            htmlFor="trust-identifier-filter"
            hint={t('trust.identifier.hint')}
            help={t('trust.identifier.help')}
          >
            <div className="trust-searchbox">
              <Icon.Search />
              <Input
                id="trust-identifier-filter"
                type="search"
                value={identifier}
                onChange={(e) => setParam('trustIdentifier', e.target.value)}
                placeholder={t('trust.identifier.placeholder')}
                aria-label={t('trust.identifier.aria')}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
          </Field>
          <TrustFilterPills active={filter} onSelect={selectFilter} />
          <div className="trust-filter-controls" role="group" aria-label={t('trust.filters.aria')}>
            <Field label={t('trust.filter.type')} htmlFor="trust-type-filter">
              <Select
                id="trust-type-filter"
                value={typeFilter}
                options={localizedOptions(TRUST_TYPE_FILTERS, t)}
                onChange={(e) =>
                  setParam('trustType', e.target.value === 'all' ? null : e.target.value)
                }
              />
            </Field>
            <Field label={t('trust.filter.status')} htmlFor="trust-status-filter">
              <Select
                id="trust-status-filter"
                value={statusFilter}
                options={localizedOptions(TRUST_STATUS_FILTERS, t)}
                onChange={(e) =>
                  setParam('trustStatus', e.target.value === 'all' ? null : e.target.value)
                }
              />
            </Field>
            <Toggle
              label={t('trust.filter.withHistory')}
              checked={historyOnly}
              onChange={(checked) => setBooleanParam('trustHistory', checked)}
            />
            <Toggle
              label={t('trust.filter.withSupplyPoint')}
              checked={supplyOnly}
              onChange={(checked) => setBooleanParam('trustSupply', checked)}
            />
          </div>

          {catalog.isLoading ? (
            <TrustResultsSkeleton label={t('trust.catalog.loading')} />
          ) : catalog.error ? (
            <ErrorNote error={catalog.error} />
          ) : trustSearchPending ? (
            <TrustResultsSkeleton label={t('trust.catalog.loading')} />
          ) : trustSearchEnabled && trustSearch.error ? (
            <ErrorNote error={trustSearch.error} />
          ) : results.providers.length === 0 && results.services.length === 0 ? (
            <EmptyState title={t('trust.search.noResults.title')}>
              <p>
                {t('trust.search.noResults.body', {
                  term: identifier.trim() || term.trim() || t(filterLabel(filter)),
                })}
              </p>
            </EmptyState>
          ) : (
            <div className="trust-results" aria-live="polite">
              <p className="trust-results__count muted">
                {t('trust.search.count', {
                  providers: results.providers.length,
                  services: results.services.length,
                })}
              </p>
              {results.providers.length ? (
                <TrustResultGroup title={t('trust.results.providers')}>
                  <ul className="trust-picklist" aria-label={t('trust.results.providers')}>
                    {results.providers.map((provider) => (
                      <li key={provider.id}>
                        <ProviderPick
                          provider={provider}
                          selected={provider.id === selectedProvider}
                          onSelect={() => selectProvider(provider.id)}
                        />
                      </li>
                    ))}
                  </ul>
                </TrustResultGroup>
              ) : null}
              {results.services.length ? (
                <TrustResultGroup title={t('trust.results.services')}>
                  <ul className="trust-picklist" aria-label={t('trust.results.services')}>
                    {results.services.map((service) => (
                      <li key={service.id}>
                        <ServicePick
                          service={service}
                          selected={service.id === selectedService}
                          onSelect={() => selectService(service.id)}
                        />
                      </li>
                    ))}
                  </ul>
                </TrustResultGroup>
              ) : null}
            </div>
          )}
        </div>

        <div className="trust-explorer__detail">
          {selectedService ? (
            <ServiceDetail
              id={selectedService}
              onSelectProvider={selectProvider}
              identifierMatch={selectedServiceIdentifierMatch}
            />
          ) : selectedProvider ? (
            <ProviderDetail id={selectedProvider} onSelectService={selectService} />
          ) : (
            <EmptyState title={t('trust.detail.empty.title')}>
              <p>{t('trust.detail.empty.body')}</p>
            </EmptyState>
          )}
        </div>
      </div>
    </Card>
  );
}

/**
 * The two domains this surface holds are unrelated jobs — the eIDAS Trusted List (scheme status +
 * provider/service catalogue) and the local time-stamp authority (RFC 3161 diagnostics + record
 * picker) — and stacking all three panels on one scroll made the TSA fact tables read as cramped
 * side-by-side columns. They are now sub-tabs, mirroring the second level of the PDF validator
 * ({@link TechnicalValidatorSection}): TSL is the default and owns the bare `/tools/trust` address,
 * TSA lives at `/tools/trust/tsa`, and the switch pushes history so Back returns to the sibling tab.
 */
export type TrustSectionId = 'tsl' | 'tsa';

const DEFAULT_TRUST_SECTION: TrustSectionId = 'tsl';

/** An unknown segment falls back to the Trusted List rather than blanking the panel. */
export function parseTrustSection(value: string | null | undefined): TrustSectionId {
  return value === 'tsa' ? 'tsa' : DEFAULT_TRUST_SECTION;
}

export function TrustCatalogPage() {
  const st = useTrustSectionsT();
  // Second level under `/tools/trust`. The Trusted List is the default, so it carries no segment of
  // its own — `/tools/trust` stays the canonical link to it — while TSA is `/tools/trust/tsa`.
  const { section, select: selectSection } = useSectionNav<TrustSectionId>({
    base: '/tools/trust',
    parse: parseTrustSection,
    fallback: DEFAULT_TRUST_SECTION,
  });

  return (
    <div className="stack">
      <SubNav
        items={[
          { id: 'tsl', label: st('tools.trust.section.tsl'), icon: <Icon.Seal /> },
          { id: 'tsa', label: st('tools.trust.section.tsa'), icon: <Icon.Calendar /> },
        ]}
        active={section}
        onSelect={selectSection}
        ariaLabel={st('tools.trust.subnav.aria')}
      />

      {/* Replays the enter animation on sub-tab switch, keyed on the sub-section so the panels'
          own URL-backed state (search terms, a selected record) does not re-key. */}
      <div className="route-transition" key={section} data-subanim-key={section}>
        {section === 'tsa' ? (
          <TsaToolingPanel />
        ) : (
          <div className="stack">
            <TrustStatusPanel />
            <TrustCatalogExplorer />
          </div>
        )}
      </div>
    </div>
  );
}
