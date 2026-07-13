import { useMemo, useState } from 'react';
import { ApiError } from '../../api/client';
import { useEntityChronology } from '../../api/hooks';
import type {
  EntityChronologyEvent,
  EntityChronologyMermaid,
  EntityChronologyView,
} from '../../api/types';
import { useT, type TFunction } from '../../i18n';
import { Badge, Button, Card, EmptyState, ErrorNote, Icon, Loading, useToast } from '../../ui';

type MermaidKey = keyof EntityChronologyMermaid;

const MERMAID_KEYS: MermaidKey[] = ['shareholders', 'organs', 'relationships'];

function mermaidLabel(t: TFunction, key: MermaidKey): string {
  if (key === 'shareholders') return t('entities.chronology.graph.shareholders');
  if (key === 'organs') return t('entities.chronology.graph.organs');
  return t('entities.chronology.graph.relationships');
}

function graphText(view: EntityChronologyView, key: MermaidKey): string {
  return view.mermaid[key].trim();
}

function actorsText(actors: string[], t: TFunction) {
  return actors.length > 0 ? actors.join(', ') : t('entities.chronology.none');
}

function mermaidNodeLabel(value: string): string {
  const trimmed = value.trim().replace(/;$/, '').replace(/:::[\w-]+$/, '').trim();
  const bracket = trimmed.match(/\[\s*"?([^"\]]+)"?\s*\]/);
  if (bracket?.[1]) return bracket[1].trim();
  const paren = trimmed.match(/\(\s*"?([^")]+)"?\s*\)/);
  if (paren?.[1]) return paren[1].trim();
  const brace = trimmed.match(/\{\s*"?([^"}]+)"?\s*\}/);
  if (brace?.[1]) return brace[1].trim();
  return trimmed.replace(/^["']|["']$/g, '').trim();
}

function mermaidPathRows(value: string): { from: string; to: string }[] {
  const lines = value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  const nodeLabels = new Map<string, string>();

  for (const line of lines) {
    const declaration = line.match(
      /^([A-Za-z_][\w-]*)\s*(\[[^\]]+\]|\([^)]+\)|\{[^}]+\})\s*;?$/,
    );
    if (declaration?.[1] && declaration[2]) {
      nodeLabels.set(declaration[1], mermaidNodeLabel(declaration[2]));
    }
  }

  function endpointLabel(endpoint: string): string {
    const trimmed = endpoint.trim().replace(/;$/, '');
    return nodeLabels.get(trimmed) ?? mermaidNodeLabel(trimmed);
  }

  return lines.flatMap((line) => {
    if (/^(graph|flowchart|timeline|sequenceDiagram|classDiagram|stateDiagram)/i.test(line)) {
      return [];
    }

    const arrow = line.match(/^(.+?)\s*(?:-->|---|-.->|==>)\s*(?:\|(.+?)\|\s*)?(.+)$/);
    if (arrow?.[1] && arrow[3]) {
      const to = endpointLabel(arrow[3]);
      const edgeLabel = arrow[2] ? mermaidNodeLabel(arrow[2]) : '';
      return [
        {
          from: endpointLabel(arrow[1]),
          to: edgeLabel ? `${to} (${edgeLabel})` : to,
        },
      ];
    }

    const timeline = line.match(/^(.+?)\s*:\s*(.+)$/);
    if (timeline?.[1] && timeline[2]) {
      return [{ from: mermaidNodeLabel(timeline[1]), to: mermaidNodeLabel(timeline[2]) }];
    }

    return [];
  });
}

function ChronologyVisualTimeline({
  events,
  t,
}: {
  events: EntityChronologyEvent[];
  t: TFunction;
}) {
  if (events.length === 0) return null;

  return (
    <ol className="chronology-rail" aria-label={t('entities.chronology.title')}>
      {events.map((event, index) => (
        <li
          className="chronology-rail__item"
          key={`${event.source_inscription}-${event.kind}-${event.date ?? index}`}
        >
          <span className="chronology-rail__marker" aria-hidden="true">
            {index + 1}
          </span>
          <div className="chronology-rail__body">
            <div className="chronology-rail__head">
              {event.date ? (
                <time className="mono" dateTime={event.date}>
                  {event.date}
                </time>
              ) : (
                <span className="muted">{t('entities.chronology.none')}</span>
              )}
              <Badge tone="accent">
                {t('entities.chronology.sourceInscription', {
                  inscription: event.source_inscription,
                })}
              </Badge>
              <code className="mono">{event.kind}</code>
            </div>
            <p>{event.description}</p>
            <p className="muted">{actorsText(event.actors, t)}</p>
          </div>
        </li>
      ))}
    </ol>
  );
}

function ChronologyTimeline({ view, t }: { view: EntityChronologyView; t: TFunction }) {
  if (view.events.length === 0) {
    return <p className="muted">{t('entities.chronology.events.empty')}</p>;
  }

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>{t('entities.chronology.table.date')}</th>
            <th>{t('entities.chronology.table.kind')}</th>
            <th>{t('entities.chronology.table.description')}</th>
            <th>{t('entities.chronology.table.source')}</th>
            <th>{t('entities.chronology.table.actors')}</th>
          </tr>
        </thead>
        <tbody>
          {view.events.map((event, index) => (
            <tr key={`${event.source_inscription}-${event.kind}-${event.date ?? index}`}>
              <td>
                {event.date ? (
                  <time className="mono" dateTime={event.date}>
                    {event.date}
                  </time>
                ) : (
                  t('entities.chronology.none')
                )}
              </td>
              <td>
                <code className="mono">{event.kind}</code>
              </td>
              <td>{event.description}</td>
              <td>
                <code className="mono">
                  {t('entities.chronology.sourceInscription', {
                    inscription: event.source_inscription,
                  })}
                </code>
              </td>
              <td>{actorsText(event.actors, t)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function GraphPathSummary({
  graphs,
  t,
}: {
  graphs: { key: MermaidKey; label: string; value: string }[];
  t: TFunction;
}) {
  return (
    <div className="chronology-graph-grid">
      {graphs.map((graph) => {
        const paths = mermaidPathRows(graph.value);
        return (
          <section className="chronology-graph-card" key={graph.key} aria-label={graph.label}>
            <h4>{graph.label}</h4>
            {paths.length > 0 ? (
              <ul className="chronology-paths">
                {paths.map((path, index) => (
                  <li key={`${path.from}-${path.to}-${index}`}>
                    <span>{path.from}</span>
                    <span>-&gt;</span>
                    <span>{path.to}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">{t('entities.chronology.graph.empty')}</p>
            )}
          </section>
        );
      })}
    </div>
  );
}

function ChronologyAnalytics({ view, t }: { view: EntityChronologyView; t: TFunction }) {
  const graphCounts = MERMAID_KEYS.map((key) => ({
    key,
    label: mermaidLabel(t, key),
    counts: view.analytics.graph[key],
  }));
  const sourceList =
    view.analytics.source_inscriptions.length > 0
      ? view.analytics.source_inscriptions
          .map((inscription) => t('entities.chronology.sourceInscription', { inscription }))
          .join(', ')
      : t('entities.chronology.none');

  return (
    <section className="chronology-analytics" aria-label={t('entities.chronology.analytics.title')}>
      <div className="chronology-analytics__head">
        <h4>{t('entities.chronology.analytics.title')}</h4>
        <p className="muted">{t('entities.chronology.analytics.notice')}</p>
      </div>

      <dl className="chronology-metrics">
        <div>
          <dt>{t('entities.chronology.analytics.totalEvents')}</dt>
          <dd>{view.analytics.total_events}</dd>
        </div>
        <div>
          <dt>{t('entities.chronology.analytics.datedEvents')}</dt>
          <dd>{view.analytics.dated_events}</dd>
        </div>
        <div>
          <dt>{t('entities.chronology.analytics.undatedEvents')}</dt>
          <dd>{view.analytics.undated_events}</dd>
        </div>
        <div>
          <dt>{t('entities.chronology.analytics.sourceInscriptions')}</dt>
          <dd>{view.analytics.source_inscription_count}</dd>
        </div>
      </dl>

      <div className="chronology-analytics__detail">
        <div>
          <h5>{t('entities.chronology.analytics.eventKinds')}</h5>
          {view.analytics.event_kinds.length > 0 ? (
            <ul className="chronology-analytics__list">
              {view.analytics.event_kinds.map((row) => (
                <li key={row.kind}>
                  {t('entities.chronology.analytics.kindCount', {
                    kind: row.kind,
                    count: row.count,
                  })}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">{t('entities.chronology.events.empty')}</p>
          )}
        </div>

        <div>
          <h5>{t('entities.chronology.analytics.sourceList')}</h5>
          <p className="mono chronology-analytics__sources">{sourceList}</p>
        </div>

        <div>
          <h5>{t('entities.chronology.analytics.graphCounts')}</h5>
          <ul className="chronology-analytics__list">
            {graphCounts.map((graph) => (
              <li key={graph.key}>
                {t('entities.chronology.analytics.graphCount', {
                  label: graph.label,
                  nodes: graph.counts.nodes,
                  edges: graph.counts.edges,
                  warnings: graph.counts.warnings,
                })}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

function MermaidSource({
  label,
  value,
  copied,
  onCopy,
  t,
}: {
  label: string;
  value: string;
  copied: boolean;
  onCopy: () => void;
  t: TFunction;
}) {
  return (
    <details open className="stack--tight">
      <summary className="card__label">{label}</summary>
      {value ? (
        <>
          <textarea
            aria-label={t('entities.chronology.mermaid.aria', { label })}
            className="control control--textarea mono"
            readOnly
            rows={Math.min(10, Math.max(4, value.split('\n').length + 1))}
            value={value}
          />
          <div className="form__actions">
            <Button type="button" icon={copied ? <Icon.Check /> : <Icon.Copy />} onClick={onCopy}>
              {copied ? t('common.copied') : t('entities.chronology.copyMermaid')}
            </Button>
          </div>
        </>
      ) : (
        <p className="muted">{t('entities.chronology.graph.empty')}</p>
      )}
    </details>
  );
}

export function EntityChronologyPanel({ entityId }: { entityId: string }) {
  const t = useT();
  const toast = useToast();
  const chronology = useEntityChronology(entityId);
  const [copied, setCopied] = useState<MermaidKey | null>(null);

  const graphs = useMemo(
    () =>
      chronology.data
        ? MERMAID_KEYS.map((key) => ({
            key,
            label: mermaidLabel(t, key),
            value: graphText(chronology.data, key),
          }))
        : [],
    [chronology.data, t],
  );

  async function copyGraph(key: MermaidKey, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(key);
      window.setTimeout(() => setCopied(null), 1500);
      toast.success(t('entities.chronology.toast.copied'));
    } catch {
      toast.error(t('entities.chronology.toast.copyFailed'));
    }
  }

  if (chronology.isLoading) {
    return (
      <Card title={t('entities.chronology.title')}>
        <Loading label={t('entities.chronology.loading')} />
      </Card>
    );
  }

  if (chronology.error) {
    if (chronology.error instanceof ApiError && chronology.error.status === 404) {
      return (
        <Card title={t('entities.chronology.title')}>
          <EmptyState title={t('entities.chronology.empty.title')}>
            <p>{t('entities.chronology.empty.body')}</p>
          </EmptyState>
        </Card>
      );
    }
    return <ErrorNote error={chronology.error} />;
  }

  if (!chronology.data) return null;

  return (
    <Card title={t('entities.chronology.title')}>
      <div className="stack">
        <p className="muted">{t('entities.chronology.boundary')}</p>

        <ChronologyVisualTimeline events={chronology.data.events} t={t} />

        <GraphPathSummary graphs={graphs} t={t} />

        <ChronologyAnalytics view={chronology.data} t={t} />

        <ChronologyTimeline view={chronology.data} t={t} />

        <div className="stack">
          {graphs.map((graph) => (
            <MermaidSource
              key={graph.key}
              label={graph.label}
              value={graph.value}
              copied={copied === graph.key}
              onCopy={() => void copyGraph(graph.key, graph.value)}
              t={t}
            />
          ))}
        </div>
      </div>
    </Card>
  );
}
