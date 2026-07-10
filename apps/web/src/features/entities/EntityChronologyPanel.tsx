import { useMemo, useState } from 'react';
import { ApiError } from '../../api/client';
import { useEntityChronology } from '../../api/hooks';
import type { EntityChronologyMermaid, EntityChronologyView } from '../../api/types';
import { useT, type TFunction } from '../../i18n';
import { Button, Card, EmptyState, ErrorNote, Icon, Loading, useToast } from '../../ui';

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
