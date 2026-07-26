import {
  usePauseSearchIndex,
  useRebuildSearchIndex,
  useResumeSearchIndex,
  useSearchStatus,
} from '../../api/hooks';
import type { SearchIndexPhase, SearchSettings, SearchStatusResponse } from '../../api/types';
import { useActiveLocale } from '../../i18n';
import { type SearchCopyKey, useSearchT } from '../../i18n/searchFallback';
import {
  Badge,
  Button,
  Card,
  DateTime,
  ErrorNote,
  Field,
  InlineWarning,
  Input,
  SkeletonDeflist,
  Table,
  Toggle,
} from '../../ui';
import './SearchSettingsPanel.css';

interface SearchSettingsPanelProps {
  value: SearchSettings;
  canEditSettings: boolean;
  onChange: <K extends keyof SearchSettings>(key: K, value: SearchSettings[K]) => void;
}

interface BoundedField {
  key: Exclude<keyof SearchSettings, 'enabled'>;
  label: SearchCopyKey;
  hint: SearchCopyKey;
  min: number;
  max: number;
}

const BOUNDED_FIELDS: readonly BoundedField[] = [
  {
    key: 'batch_size',
    label: 'admin.search.batchSize.label',
    hint: 'admin.search.batchSize.hint',
    min: 16,
    max: 5_000,
  },
  {
    key: 'interval_seconds',
    label: 'admin.search.interval.label',
    hint: 'admin.search.interval.hint',
    min: 5,
    max: 86_400,
  },
  {
    key: 'queue_capacity',
    label: 'admin.search.queueCapacity.label',
    hint: 'admin.search.queueCapacity.hint',
    min: 1,
    max: 1_024,
  },
  {
    key: 'result_limit',
    label: 'admin.search.resultLimit.label',
    hint: 'admin.search.resultLimit.hint',
    min: 1,
    max: 500,
  },
  {
    key: 'snippet_chars',
    label: 'admin.search.snippetChars.label',
    hint: 'admin.search.snippetChars.hint',
    min: 32,
    max: 2_000,
  },
  {
    key: 'facet_limit',
    label: 'admin.search.facetLimit.label',
    hint: 'admin.search.facetLimit.hint',
    min: 1,
    max: 200,
  },
  {
    key: 'max_content_chars',
    label: 'admin.search.maxContent.label',
    hint: 'admin.search.maxContent.hint',
    min: 1_000,
    max: 1_000_000,
  },
  {
    key: 'max_total_content_chars',
    label: 'admin.search.maxTotalContent.label',
    hint: 'admin.search.maxTotalContent.hint',
    min: 100_000,
    max: 100_000_000,
  },
  {
    key: 'event_retention_days',
    label: 'admin.search.retention.label',
    hint: 'admin.search.retention.hint',
    min: 1,
    max: 36_500,
  },
  {
    key: 'min_query_chars',
    label: 'admin.search.minQuery.label',
    hint: 'admin.search.minQuery.hint',
    min: 2,
    max: 8,
  },
];

function bounded(raw: string, current: number, min: number, max: number): number {
  if (raw.trim() === '') return current;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return current;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function phaseTone(phase: SearchIndexPhase): 'neutral' | 'info' | 'ok' | 'warn' | 'error' {
  if (phase === 'idle') return 'ok';
  if (phase === 'error') return 'error';
  if (phase === 'paused' || phase === 'disabled' || phase === 'shutting_down') return 'warn';
  return 'info';
}

function formatNumber(value: number, locale: string): string {
  return new Intl.NumberFormat(locale).format(value);
}

function StatusValue({ date, fallback }: { date: string | null | undefined; fallback: string }) {
  return date ? <DateTime value={date} evidentiary /> : <>{fallback}</>;
}

function SearchStatusTable({ status }: { status: SearchStatusResponse }) {
  const st = useSearchT();
  const locale = useActiveLocale();
  const queueDepth = status.queue_depth;
  const queueCapacity = status.queue_capacity;
  const progressMax = Math.max(status.total, 1);
  const phaseKey = `admin.search.phase.${status.phase}` as SearchCopyKey;
  const rows = [
    {
      label: st('admin.search.status.phase'),
      value: <Badge tone={phaseTone(status.phase)}>{st(phaseKey)}</Badge>,
    },
    {
      label: st('admin.search.status.documents'),
      value: st('admin.search.status.documentsValue', {
        count: formatNumber(status.document_count, locale),
        truncated: formatNumber(status.truncated_document_count, locale),
      }),
    },
    {
      label: st('admin.search.status.generation'),
      value: formatNumber(status.generation, locale),
    },
    {
      label: st('admin.search.status.progress'),
      value: (
        <span className="search-admin-progress">
          <progress max={progressMax} value={Math.min(status.processed, progressMax)} />
          <span>
            {formatNumber(status.processed, locale)} / {formatNumber(status.total, locale)}
          </span>
        </span>
      ),
    },
    {
      label: st('admin.search.status.queue'),
      value:
        queueDepth === undefined || queueCapacity === undefined
          ? st('admin.search.status.none')
          : st('admin.search.status.queueValue', {
              depth: formatNumber(queueDepth, locale),
              capacity: formatNumber(queueCapacity, locale),
            }),
    },
    {
      label: st('admin.search.status.content'),
      value:
        status.content_budget_chars === undefined
          ? st('admin.search.status.contentRedactedValue', {
              used: formatNumber(status.indexed_content_chars, locale),
            })
          : st('admin.search.status.contentValue', {
              used: formatNumber(status.indexed_content_chars, locale),
              budget: formatNumber(status.content_budget_chars, locale),
            }),
    },
    {
      label: st('admin.search.status.updated'),
      value: <DateTime value={status.updated_at} evidentiary />,
    },
    {
      label: st('admin.search.status.completed'),
      value: (
        <StatusValue date={status.last_completed_at} fallback={st('admin.search.status.none')} />
      ),
    },
    {
      label: st('admin.search.status.event'),
      value:
        status.last_event_seq === null
          ? st('admin.search.status.none')
          : formatNumber(status.last_event_seq, locale),
    },
    {
      label: st('admin.search.status.worker'),
      value: status.worker_thread ?? st('admin.search.status.none'),
    },
    {
      label: st('admin.search.status.writer'),
      value:
        status.projection_writer === undefined
          ? st('admin.search.status.none')
          : status.projection_writer
            ? st('admin.search.status.yes')
            : st('admin.search.status.no'),
    },
    {
      label: st('admin.search.status.dropped'),
      value:
        status.dropped_commands === undefined
          ? st('admin.search.status.none')
          : formatNumber(status.dropped_commands, locale),
    },
  ];

  return (
    <div className="stack--tight">
      <Table
        className="search-admin-status-table"
        caption={st('admin.search.status.title')}
        head={
          <tr>
            <th scope="col">{st('admin.search.status.metric')}</th>
            <th scope="col">{st('admin.search.status.value')}</th>
          </tr>
        }
      >
        {rows.map((row) => (
          <tr key={row.label}>
            <th scope="row">{row.label}</th>
            <td>{row.value}</td>
          </tr>
        ))}
      </Table>
      {status.content_budget_exhausted ? (
        <InlineWarning tone="warn" title={st('search.state.budget.title')}>
          {status.content_budget_chars === undefined
            ? st('search.state.budget.redactedBody')
            : st('search.state.budget.body', {
                used: formatNumber(status.indexed_content_chars, locale),
                budget: formatNumber(status.content_budget_chars, locale),
              })}
        </InlineWarning>
      ) : status.content_truncated ? (
        <InlineWarning tone="warn" title={st('search.state.truncated.title')}>
          {st('search.state.truncated.body', {
            count: formatNumber(status.truncated_document_count, locale),
          })}
        </InlineWarning>
      ) : null}
      {status.last_error ? (
        <InlineWarning tone="error" title={st('admin.search.status.error')}>
          <p>{status.last_error}</p>
          {status.error_at ? <DateTime value={status.error_at} evidentiary /> : null}
        </InlineWarning>
      ) : null}
    </div>
  );
}

export function SearchSettingsPanel({
  value,
  canEditSettings,
  onChange,
}: SearchSettingsPanelProps) {
  const st = useSearchT();
  const status = useSearchStatus(true);
  const rebuild = useRebuildSearchIndex();
  const pause = usePauseSearchIndex();
  const resume = useResumeSearchIndex();
  const commandPending = rebuild.isPending || pause.isPending || resume.isPending;
  const phase = status.data?.phase;
  const commandError = rebuild.error ?? pause.error ?? resume.error;

  return (
    <div className="stack search-admin-panel">
      <p className="field__hint">{st('admin.search.intro')}</p>

      <Card title={st('admin.search.status.title')}>
        {status.isLoading ? (
          <SkeletonDeflist rows={8} />
        ) : status.error ? (
          <ErrorNote error={status.error} />
        ) : status.data ? (
          <SearchStatusTable status={status.data} />
        ) : null}
      </Card>

      <Card title={st('admin.search.actions.title')}>
        <div className="stack--tight">
          <p className="field__hint">{st('admin.search.actions.rebuildHint')}</p>
          <div className="row-wrap">
            <Button
              type="button"
              variant="secondary"
              disabled={!value.enabled || phase === 'paused' || commandPending}
              onClick={() => rebuild.mutate()}
            >
              {rebuild.isPending
                ? st('admin.search.actions.pending')
                : st('admin.search.actions.rebuild')}
            </Button>
            <Button
              type="button"
              variant="secondary"
              disabled={
                phase === 'paused' ||
                phase === 'disabled' ||
                phase === 'shutting_down' ||
                commandPending
              }
              onClick={() => pause.mutate()}
            >
              {pause.isPending
                ? st('admin.search.actions.pending')
                : st('admin.search.actions.pause')}
            </Button>
            <Button
              type="button"
              variant="secondary"
              disabled={!value.enabled || phase !== 'paused' || commandPending}
              onClick={() => resume.mutate()}
            >
              {resume.isPending
                ? st('admin.search.actions.pending')
                : st('admin.search.actions.resume')}
            </Button>
          </div>
          {commandError ? <ErrorNote error={commandError} /> : null}
        </div>
      </Card>

      <Card title={st('admin.search.settings.title')}>
        {!canEditSettings ? (
          <InlineWarning tone="info">{st('admin.search.settings.permission')}</InlineWarning>
        ) : null}
        <fieldset className="settings-fieldset" disabled={!canEditSettings}>
          <div className="form settings-rows search-settings-rows">
            <Toggle
              label={st('admin.search.enabled.label')}
              checked={value.enabled}
              onChange={(enabled) => onChange('enabled', enabled)}
            />
            <p className="field__hint">{st('admin.search.enabled.hint')}</p>
            {BOUNDED_FIELDS.map((field) => (
              <Field
                key={field.key}
                label={st(field.label)}
                htmlFor={`search-setting-${field.key}`}
                hint={st(field.hint)}
              >
                <Input
                  id={`search-setting-${field.key}`}
                  type="number"
                  min={field.min}
                  max={field.max}
                  step={1}
                  value={value[field.key]}
                  onChange={(event) =>
                    onChange(
                      field.key,
                      bounded(event.target.value, value[field.key], field.min, field.max),
                    )
                  }
                />
              </Field>
            ))}
          </div>
        </fieldset>
      </Card>
    </div>
  );
}
