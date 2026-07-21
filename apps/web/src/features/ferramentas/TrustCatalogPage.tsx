/**
 * TSL trust catalog surface for Ferramentas.
 *
 * Read-only by design: the backend exposes the parsed Trusted List state and catalog, but
 * no live refresh operation. The UI therefore mirrors the CAE/law consultation style:
 * a compact status card for scheme/source/signature validity, plus a two-pane catalog
 * explorer with URL-backed search/filter/selection and provider/service detail panes.
 */
import { useMemo, type ReactNode } from 'react';
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
  Loading,
  Select,
  SkeletonDeflist,
  Toggle,
} from '../../ui';
import type {
  TslCatalogSearchParams,
  TslCatalogView,
  TslProviderView,
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
    <section
      role="group"
      aria-label={title}
      className={`trust-detail-section${tone === 'warn' ? ' trust-detail-section--warn' : ''}`}
    >
      <h4 className="field__label trust-detail-section__title">{title}</h4>
      {children}
    </section>
  );
}

function TrustKeyValueGrid({ children }: { children: ReactNode }) {
  return <dl className="deflist deflist--tight trust-kv-grid">{children}</dl>;
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
        <TrustKeyValueGrid>
          <div>
            <dt>{t('trust.service.type')}</dt>
            <dd className="mono trust-opaque" title={record.service_type}>
              {record.service_type}
            </dd>
          </div>
          <div>
            <dt>{t('trust.service.statusStartingTime')}</dt>
            <dd className="mono">
              {record.status_starting_time ?? record.status_starting_time_raw ?? '—'}
            </dd>
          </div>
          <div>
            <dt>{t('trust.tsa.detail.grantedEffective')}</dt>
            <dd>
              {record.granted ? t('common.yes') : t('common.no')} /{' '}
              {record.effective ? t('common.yes') : t('common.no')}
            </dd>
          </div>
          <div>
            <dt>{t('trust.service.certificates')}</dt>
            <dd className="mono">{record.identities.certificates}</dd>
          </div>
        </TrustKeyValueGrid>
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
        <TrustKeyValueGrid>
          <div>
            <dt>{t('trust.detail.historyEntries')}</dt>
            <dd className="mono">{record.history_count}</dd>
          </div>
          <div>
            <dt>{t('trust.tsa.detail.classification')}</dt>
            <dd>{record.analysis.classification}</dd>
          </div>
          <div>
            <dt>{t('trust.tsa.detail.trustBasis')}</dt>
            <dd>{record.analysis.trust_basis}</dd>
          </div>
        </TrustKeyValueGrid>
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
              <TrustKeyValueGrid>
                <div>
                  <dt>{t('trust.tsa.configuredUrl')}</dt>
                  <dd className="mono">{tsa.data.summary.configured_url ?? '—'}</dd>
                </div>
                <div>
                  <dt>{t('trust.tsa.status')}</dt>
                  <dd>
                    <Badge tone={tsaStatusTone(tsa.data.summary.status)}>
                      {t(tsaStatusLabel(tsa.data.summary.status))}
                    </Badge>
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.tsa.profile')}</dt>
                  <dd>
                    {tsa.data.summary.profile.protocol} · {tsa.data.summary.profile.hash_algorithm}
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.tsa.acceptedHash')}</dt>
                  <dd className="trust-digest-cell">
                    <TsaAcceptedHash digest={tsa.data.summary.accepted_hash.digest} />
                  </dd>
                </div>
              </TrustKeyValueGrid>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.tsa.fixtureProof')}>
              <TrustKeyValueGrid>
                <div>
                  <dt>{t('trust.tsa.fixture')}</dt>
                  <dd>
                    <Badge tone={probeTone(tsa.data.summary.last_probe.status)}>
                      {t(probeLabel(tsa.data.summary.last_probe.status))}
                    </Badge>
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.status.checkedAt')}</dt>
                  {/* A probe is a record of something having happened: evidentiary. */}
                  <dd>
                    <DateTime className="mono" value={tsa.data.summary.last_probe.checked_at} evidentiary />
                  </dd>
                </div>
              </TrustKeyValueGrid>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.tsa.timestampToken')}>
              <TrustKeyValueGrid>
                <div>
                  <dt>GenTime</dt>
                  <dd className="mono">{tsa.data.summary.timestamp?.gen_time ?? '—'}</dd>
                </div>
                <div>
                  <dt>{t('trust.tsa.policySerial')}</dt>
                  <dd className="mono">
                    {tsa.data.summary.timestamp
                      ? `${tsa.data.summary.timestamp.policy} / ${tsa.data.summary.timestamp.serial_number}`
                      : '—'}
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.tsa.policyAnalysis')}</dt>
                  <dd>
                    {tsa.data.summary.policy_analysis.fixture_policy ?? '—'} ·{' '}
                    {tsa.data.summary.policy_analysis.advisory
                      ? t('trust.tsa.policyAdvisory')
                      : t('trust.tsa.policyTrusted')}
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.tsa.token')}</dt>
                  <dd className="mono">
                    {t('trust.tsa.tokenBytes', {
                      bytes: tsa.data.summary.timestamp?.token_bytes ?? '—',
                    })}
                  </dd>
                </div>
              </TrustKeyValueGrid>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.tsa.tslRecords')}>
              <TrustKeyValueGrid>
                <div>
                  <dt>{t('trust.tsa.totalTrusted')}</dt>
                  <dd className="mono">
                    {t('trust.tsa.totalTrusted.value', {
                      total: tsa.data.summary.records,
                      trusted: tsa.data.summary.trusted_records,
                    })}
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.tsa.granted')}</dt>
                  <dd className="mono">{tsa.data.summary.granted_records}</dd>
                </div>
              </TrustKeyValueGrid>
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
                <Loading label={t('trust.tsa.search.loading')} />
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
              <TrustKeyValueGrid>
                <div>
                  <dt>{t('trust.refresh.result')}</dt>
                  <dd>
                    <Badge tone={refreshOutcomeTone(status.data.last_refresh.outcome)}>
                      {t(refreshOutcomeLabel(status.data.last_refresh.outcome))}
                    </Badge>
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.refresh.attemptedAt')}</dt>
                  <dd>
                    <DateTime className="mono" value={status.data.last_refresh.attempted_at} evidentiary />
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.status.source')}</dt>
                  <dd className="mono trust-opaque">
                    {status.data.last_refresh.source_url ??
                      status.data.last_refresh.source_path ??
                      '—'}
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.refresh.records')}</dt>
                  <dd className="mono">
                    {t('trust.search.count', {
                      providers: status.data.last_refresh.providers ?? '—',
                      services: status.data.last_refresh.services ?? '—',
                    })}
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.refresh.importSignature')}</dt>
                  <dd>
                    <SignatureBadge status={status.data.last_refresh.validation.signature} />
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.status.trusted')}</dt>
                  <dd className="mono">
                    {status.data.last_refresh.trusted_esignature_services ?? '—'}
                  </dd>
                </div>
              </TrustKeyValueGrid>
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
              <TrustKeyValueGrid>
                <div>
                  <dt>{t('trust.status.scheme')}</dt>
                  <dd>{status.data.scheme_name}</dd>
                </div>
                <div>
                  <dt>{t('trust.status.operator')}</dt>
                  <dd>{status.data.scheme_operator_name}</dd>
                </div>
                <div>
                  <dt>{t('trust.status.territory')}</dt>
                  <dd className="mono">{status.data.scheme_territory}</dd>
                </div>
                <div>
                  <dt>{t('trust.status.sequence')}</dt>
                  <dd className="mono">{status.data.sequence_number ?? '—'}</dd>
                </div>
              </TrustKeyValueGrid>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.status.dates')}>
              <TrustKeyValueGrid>
                <div>
                  <dt>{t('trust.status.issueDate')}</dt>
                  {/* When the scheme operator issued this list — evidentiary. */}
                  <dd>
                    <DateTime className="mono" value={status.data.issue_date_time} evidentiary />
                  </dd>
                </div>
                <div>
                  <dt>{t('trust.status.nextUpdate')}</dt>
                  {/* A scheduled future update, not a record of an event. */}
                  <dd>
                    <DateTime className="mono" value={status.data.next_update} />
                  </dd>
                </div>
              </TrustKeyValueGrid>
            </TrustDetailSection>

            <TrustDetailSection title={t('trust.status.coverage')}>
              <TrustKeyValueGrid>
                <div>
                  <dt>{t('trust.status.providers')}</dt>
                  <dd className="mono">{status.data.providers}</dd>
                </div>
                <div>
                  <dt>{t('trust.status.services')}</dt>
                  <dd className="mono">{status.data.services}</dd>
                </div>
                <div>
                  <dt>{t('trust.status.qualified')}</dt>
                  <dd className="mono">{status.data.qualified_esignature_services}</dd>
                </div>
                <div>
                  <dt>{t('trust.status.trusted')}</dt>
                  <dd className="mono">{status.data.trusted_esignature_services}</dd>
                </div>
              </TrustKeyValueGrid>
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

function ProviderDetail({
  id,
  onSelectService,
}: {
  id: string;
  onSelectService: (id: string) => void;
}) {
  const t = useT();
  const detail = useTrustProvider(id);

  if (detail.isLoading) return <Loading label={t('trust.detail.loading')} />;
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
        <TrustKeyValueGrid>
          <div>
            <dt>{t('trust.provider.tradeNames')}</dt>
            <dd>{provider.trade_names.length ? provider.trade_names.join(', ') : '—'}</dd>
          </div>
          <div>
            <dt>{t('trust.provider.informationUris')}</dt>
            <dd>{provider.information_uris.length ? provider.information_uris.join(', ') : '—'}</dd>
          </div>
          <div>
            <dt>{t('trust.status.services')}</dt>
            <dd className="mono">{provider.services.length}</dd>
          </div>
          <div>
            <dt>{t('trust.provider.analysis')}</dt>
            <dd>
              {t('trust.provider.analysis.value', {
                granted: provider.analysis.granted_services,
                history: provider.analysis.services_with_history,
                supply: provider.analysis.services_with_supply_points,
              })}
            </dd>
          </div>
        </TrustKeyValueGrid>
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
        <ul className="trust-service-list">
          {provider.services.map((service) => (
            <li key={service.id}>
              <button
                type="button"
                className="trust-service-row"
                onClick={() => onSelectService(service.id)}
              >
                <span>
                  <span className="trust-service-row__name">{service.name}</span>
                  <span className="trust-service-row__type muted">{service.service_type}</span>
                </span>
                <ServiceFlags service={service} />
              </button>
            </li>
          ))}
        </ul>
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

  if (detail.isLoading) return <Loading label={t('trust.detail.loading')} />;
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
        <TrustKeyValueGrid>
          <div>
            <dt>{t('trust.service.type')}</dt>
            <dd className="mono trust-opaque" title={service.service_type}>
              {service.service_type}
            </dd>
          </div>
          <div>
            <dt>{t('trust.service.statusUri')}</dt>
            <dd className="mono">{service.status.uri ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('trust.service.statusStartingTime')}</dt>
            <dd className="mono">
              {service.status_starting_time ?? service.status_starting_time_raw ?? '—'}
            </dd>
          </div>
          <div>
            <dt>{t('trust.service.certificates')}</dt>
            <dd className="mono">{service.identities.certificates}</dd>
          </div>
        </TrustKeyValueGrid>
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
        <TrustKeyValueGrid>
          <div>
            <dt>{t('trust.detail.historyEntries')}</dt>
            <dd className="mono">{service.history_count}</dd>
          </div>
        </TrustKeyValueGrid>
        {service.history.length ? (
          <ul className="trust-identity-list">
            {service.history.map((entry, index) => (
              <li key={`${entry.service_type}-${entry.status.kind}-${index}`}>
                <span className="trust-identity-list__kind">{entry.status.kind}</span>
                <span>{entry.name || '—'}</span>
                <code className="mono">{entry.service_type}</code>
                <span className="muted mono">
                  {entry.status_starting_time ?? entry.status_starting_time_raw ?? '—'}
                </span>
              </li>
            ))}
          </ul>
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
            <ul className="trust-identity-list">
              {service.digital_identities.slice(0, 8).map((identity) => (
                <li key={`${identity.kind}-${identity.value}-${identity.sha256 ?? ''}`}>
                  <span className="trust-identity-list__kind">{identity.kind}</span>
                  <IdentityValue value={identity.value} />
                  {identity.sha256 && identity.sha256 !== identity.value ? (
                    <IdentityValue value={identity.sha256} />
                  ) : null}
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
            <Loading label={t('trust.catalog.loading')} />
          ) : catalog.error ? (
            <ErrorNote error={catalog.error} />
          ) : trustSearchPending ? (
            <Loading label={t('trust.catalog.loading')} />
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

export function TrustCatalogPage() {
  return (
    <div className="stack">
      <TsaToolingPanel />
      <TrustStatusPanel />
      <TrustCatalogExplorer />
    </div>
  );
}
