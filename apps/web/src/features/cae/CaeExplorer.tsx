/**
 * The CAE catalog explorer (t22-web item 3) — an extensive consultation surface for the
 * Classificação Portuguesa das Atividades Económicas, built on the endpoints that exist
 * today (no new backend routes):
 *
 *  - a **revision switch** (Rev.3 / Rev.4) that scopes every lookup and search;
 *  - **search-as-you-type** (`GET /v1/cae?search=&revision=`) to find an entry point;
 *  - a **detail pane** for the selected código: designation, level·revision badges, and
 *    a clickable **hierarchy breadcrumb** (secção → … → self, from `GET /v1/cae/{code}`)
 *    to drill UP, plus **subníveis diretos** to drill DOWN.
 *
 * The selected code + revision live in the URL (`?code=&rev=`), so a view is deep-
 * linkable and the browser Back button walks the drill history.
 *
 * ## Children (down-drill) strategy — pragmatic, no new endpoint
 * A node's direct children are enumerated by searching its código and keeping the exact
 * one-level-deeper prefix matches. This is correct for the four **numeric** levels
 * (divisão→grupo→classe→subclasse), whose children share the parent's code prefix
 * (e.g. 68 → 681 → 6811 → 68110). It degrades honestly: if the server's search page cap
 * is hit, a "refine" note is shown. The **secção → divisão** step is NOT prefix-derivable
 * (a divisão's parent is a letter, not a code prefix), and the search endpoint cannot
 * enumerate a revision to build a full client index — so a proper secção-rooted top-down
 * tree needs a backend children endpoint. The catalog crate already implements
 * `CaeCatalog::children()`; exposing it (e.g. `GET /v1/cae/{code}/children` + a secções
 * root) is the clean follow-up. Until then the explorer is search-seeded: find a code,
 * then drill up via the breadcrumb and down via the numeric subníveis.
 */
import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { CAE_CHILD_SEARCH_LIMIT, useCae, useCaeChildren, useCaeSearch } from '../../api/hooks';
import { caeLevelLabels, caeRevisionLabels } from '../../api/labels';
import { ApiError } from '../../api/client';
import { useT } from '../../i18n';
import { Badge, Card, EmptyState, ErrorNote, Input, Loading } from '../../ui';
import { CAE_REVISIONS, type CaeLevel, type CaeRevision } from '../../api/types';

/** The level one step deeper, or `null` at the terminal (subclasse). */
const NEXT_LEVEL: Record<CaeLevel, CaeLevel | null> = {
  Seccao: 'Divisao',
  Divisao: 'Grupo',
  Grupo: 'Classe',
  Classe: 'Subclasse',
  Subclasse: null,
};

/** A numeric parent whose children share its code prefix (so search-by-prefix works). */
function isPrefixDrillable(level: CaeLevel): boolean {
  return level === 'Divisao' || level === 'Grupo' || level === 'Classe';
}

/** The direct children of a numeric node: its one-level-deeper prefix descendants. */
function Subniveis({
  code,
  level,
  revision,
  onSelect,
}: {
  code: string;
  level: CaeLevel;
  revision: CaeRevision;
  onSelect: (code: string) => void;
}) {
  const t = useT();
  const childLevel = NEXT_LEVEL[level];
  const drillable = isPrefixDrillable(level);
  const children = useCaeChildren(code, revision, drillable);

  if (childLevel === null) {
    return <p className="muted">{t('cae.explorer.terminalLevel')}</p>;
  }
  if (!drillable) {
    // Secção: divisões aren't prefix-derivable — see the file header note.
    return <p className="muted">{t('cae.explorer.sectionNotDrillable')}</p>;
  }
  if (children.isLoading) return <Loading label={t('cae.explorer.subniveis.loading')} />;
  if (children.error) return <ErrorNote error={children.error} />;

  const hits = children.data ?? [];
  const direct = hits
    .filter(
      (n) => n.level === childLevel && n.code.length === code.length + 1 && n.code.startsWith(code),
    )
    .sort((a, b) => a.code.localeCompare(b.code));
  const truncated = hits.length >= CAE_CHILD_SEARCH_LIMIT;

  if (direct.length === 0) {
    return (
      <p className="muted">
        {truncated ? t('cae.explorer.noSublevels.truncated') : t('cae.explorer.noSublevels')}
      </p>
    );
  }

  return (
    <>
      <ul className="cae-tree">
        {direct.map((n) => (
          <li key={`${n.code}-${n.revision}`}>
            <button
              type="button"
              className="cae-tree__node"
              onClick={() => onSelect(n.code)}
              title={n.designation}
            >
              <code className="mono cae-tree__code">{n.code}</code>
              <span className="cae-tree__designation">{n.designation}</span>
            </button>
          </li>
        ))}
      </ul>
      {truncated ? <p className="muted">{t('cae.explorer.tooManyResults')}</p> : null}
    </>
  );
}

/** The resolved detail for the selected code: breadcrumb, designation, badges, subníveis. */
function CaeDetail({
  code,
  revision,
  onSelect,
}: {
  code: string;
  revision: CaeRevision;
  onSelect: (code: string) => void;
}) {
  const t = useT();
  const entry = useCae(code, revision);

  if (entry.isLoading) return <Loading label={t('cae.explorer.resolvingCode')} />;
  if (entry.error) {
    const status = entry.error instanceof ApiError ? entry.error.status : 0;
    if (status === 404) {
      return (
        <EmptyState title={t('cae.explorer.codeNotFound.title')}>
          <p>
            {t('cae.explorer.codeNotFound.body', {
              code,
              revision: caeRevisionLabels[revision],
            })}
          </p>
        </EmptyState>
      );
    }
    return <ErrorNote error={entry.error} />;
  }

  const e = entry.data;
  if (!e) return null;
  const hierarchy = e.hierarchy ?? [];

  return (
    <div className="stack--tight">
      {hierarchy.length > 1 ? (
        <nav className="cae-breadcrumb" aria-label={t('cae.explorer.breadcrumb.aria')}>
          {hierarchy.map((node, i) => (
            <span key={`${node.code}-${node.revision}`} className="cae-breadcrumb__item">
              {i > 0 ? (
                <span className="cae-breadcrumb__sep" aria-hidden="true">
                  ›
                </span>
              ) : null}
              {node.code === e.code ? (
                <span className="cae-breadcrumb__current mono" title={node.designation}>
                  {node.code}
                </span>
              ) : (
                <button
                  type="button"
                  className="cae-breadcrumb__link mono"
                  onClick={() => onSelect(node.code)}
                  title={node.designation}
                >
                  {node.code}
                </button>
              )}
            </span>
          ))}
        </nav>
      ) : null}

      <div className="cae-detail__head">
        <code className="mono cae-detail__code">{e.code}</code>
        <Badge tone="accent">{caeLevelLabels[e.level]}</Badge>
        <Badge tone="neutral">{caeRevisionLabels[e.revision]}</Badge>
      </div>
      <p className="cae-detail__designation">{e.designation}</p>

      <div>
        <p className="field__label">{t('cae.explorer.directSublevels.label')}</p>
        <Subniveis code={e.code} level={e.level} revision={e.revision} onSelect={onSelect} />
      </div>
    </div>
  );
}

export function CaeExplorer() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const revision: CaeRevision = params.get('rev') === 'Rev3' ? 'Rev3' : 'Rev4';
  const selectedCode = params.get('code') ?? '';

  const [term, setTerm] = useState('');
  const [debounced, setDebounced] = useState('');
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(term), 180);
    return () => window.clearTimeout(timer);
  }, [term]);

  const search = useCaeSearch(debounced, revision);
  const active = debounced.trim().length > 0;
  const results = search.data ?? [];

  function select(code: string) {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      p.set('code', code);
      p.set('rev', revision);
      return p;
    });
  }

  function changeRevision(rev: CaeRevision) {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        p.set('rev', rev);
        return p;
      },
      { replace: true },
    );
  }

  return (
    <Card title={t('cae.explorer.title')}>
      <div className="cae-explorer">
        <div className="cae-explorer__nav">
          <div className="cae-revswitch" role="group" aria-label={t('cae.explorer.revswitch.aria')}>
            {CAE_REVISIONS.map((rev) => (
              <button
                key={rev}
                type="button"
                className={rev === revision ? 'cae-revswitch__btn is-active' : 'cae-revswitch__btn'}
                aria-pressed={rev === revision}
                onClick={() => changeRevision(rev)}
              >
                {caeRevisionLabels[rev]}
              </button>
            ))}
          </div>

          <Input
            type="search"
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            placeholder={t('cae.explorer.search.placeholder')}
            aria-label={t('cae.explorer.search.aria')}
            autoComplete="off"
          />

          {!active ? (
            <p className="muted cae-search-hint">{t('cae.explorer.searchHint')}</p>
          ) : search.isLoading ? (
            <Loading label={t('cae.explorer.searching')} />
          ) : search.error ? (
            <ErrorNote error={search.error} />
          ) : results.length === 0 ? (
            <EmptyState title={t('cae.explorer.noResults.title')}>
              <p>{t('cae.explorer.noResults.body', { term: debounced })}</p>
            </EmptyState>
          ) : (
            <ul className="cae-picklist">
              {results.map((node) => (
                <li key={`${node.code}-${node.revision}`}>
                  <button
                    type="button"
                    className={node.code === selectedCode ? 'cae-pick is-current' : 'cae-pick'}
                    onClick={() => select(node.code)}
                  >
                    <span className="cae-pick__head">
                      <code className="mono cae-pick__code">{node.code}</code>
                      <span className="cae-pick__meta muted">
                        {caeLevelLabels[node.level]} · {caeRevisionLabels[node.revision]}
                      </span>
                    </span>
                    <span className="cae-pick__designation">{node.designation}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="cae-explorer__detail">
          {selectedCode ? (
            <CaeDetail code={selectedCode} revision={revision} onSelect={select} />
          ) : (
            <EmptyState title={t('cae.explorer.noSelection.title')}>
              <p>{t('cae.explorer.noSelection.body')}</p>
            </EmptyState>
          )}
        </div>
      </div>
    </Card>
  );
}
