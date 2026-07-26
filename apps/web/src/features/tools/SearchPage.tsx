import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useFullSearch, useSearchStatus } from '../../api/hooks';
import type {
  SearchFacets,
  SearchHit,
  SearchKind,
  SearchQueryParams,
  SearchRelationFacet,
  SearchStatusResponse,
} from '../../api/types';
import { useActiveLocale } from '../../i18n';
import { type SearchCopyKey, useSearchT } from '../../i18n/searchFallback';
import {
  Badge,
  Button,
  ButtonLink,
  DateTime,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  InlineWarning,
  Input,
  Select,
  SkeletonList,
} from '../../ui';
import { usePermissions } from '../session/permissions';
import './SearchPage.css';

export const SEARCH_KINDS = [
  'act',
  'entity',
  'book',
  'template',
  'law_article',
  'operational_action',
  'ledger_event',
  'follow_up',
  'imported_document',
  'paper_book',
  'ocr_draft',
  'generated_document',
] as const satisfies readonly SearchKind[];

const SEARCH_KIND_SET = new Set<string>(SEARCH_KINDS);
const RESULT_PAGE_SIZE = 25;

function namespacedId(id: string, namespace: string): string | null {
  const prefix = `${namespace}:`;
  return id.startsWith(prefix) ? id.slice(prefix.length) : null;
}

function encoded(value: string): string {
  return encodeURIComponent(value);
}

/**
 * Resolve the closest existing product surface for every indexed family. A result without the
 * relation needed by its owning surface deliberately has no action instead of inventing a 404.
 */
export function searchHitRoute(hit: SearchHit): string | null {
  const entityId = hit.entity_id ?? namespacedId(hit.id, 'entity');
  const bookId = hit.book_id ?? namespacedId(hit.id, 'book');
  const actId = hit.act_id ?? namespacedId(hit.id, 'act');

  switch (hit.kind) {
    case 'entity':
      return entityId ? `/entities/${encoded(entityId)}` : null;
    case 'book':
      return bookId ? `/books/${encoded(bookId)}` : null;
    case 'act':
      return actId ? `/acts/${encoded(actId)}` : null;
    case 'follow_up':
      return hit.act_id ? `/acts/${encoded(hit.act_id)}` : null;
    case 'imported_document': {
      if (!hit.act_id) return null;
      const documentId = namespacedId(hit.id, 'imported_document');
      const params = documentId
        ? `?focus=import-review&imported_document_id=${encoded(documentId)}#imported-documents`
        : '?focus=import-review#imported-documents';
      return `/acts/${encoded(hit.act_id)}${params}`;
    }
    case 'generated_document': {
      if (!hit.act_id) return null;
      const documentId = namespacedId(hit.id, 'generated_document');
      const params = documentId
        ? `?focus=dispatch-evidence&generated_document_id=${encoded(documentId)}#generated-dispatch-evidence`
        : '?focus=dispatch-evidence#generated-dispatch-evidence';
      return `/acts/${encoded(hit.act_id)}${params}`;
    }
    case 'paper_book':
    case 'ocr_draft':
      return hit.book_id ? `/books/${encoded(hit.book_id)}/imports` : null;
    case 'template': {
      if (hit.id.startsWith('template:library:')) return '/templates';
      const userId = namespacedId(hit.id, 'template:user');
      const templateId = userId ?? namespacedId(hit.id, 'template');
      return templateId ? `/templates/${encoded(templateId)}` : '/templates';
    }
    case 'law_article': {
      const source = namespacedId(hit.id, 'law');
      if (!source) return '/tools/legislation';
      const separator = source.lastIndexOf(':');
      if (separator <= 0 || separator === source.length - 1) return '/tools/legislation';
      const diploma = source.slice(0, separator);
      const article = source.slice(separator + 1);
      return `/tools/legislation?diploma=${encoded(diploma)}&artigo=${encoded(article)}`;
    }
    case 'ledger_event':
      return '/archive';
    case 'operational_action':
      if (hit.act_id) return `/acts/${encoded(hit.act_id)}`;
      if (hit.book_id) return `/books/${encoded(hit.book_id)}`;
      if (hit.entity_id) return `/entities/${encoded(hit.entity_id)}`;
      return '/dashboard/queue';
  }
}

function selectedKinds(value: string): SearchKind[] {
  return value.split(',').filter((kind): kind is SearchKind => SEARCH_KIND_SET.has(kind));
}

function optionalParam(params: URLSearchParams, name: string): string | undefined {
  return params.get(name)?.trim() || undefined;
}

function facetOptions(
  values: Record<string, number>,
  selected: string | undefined,
  allLabel: string,
): { value: string; label: string; disabled?: boolean }[] {
  const entries = Object.entries(values);
  if (selected && !Object.hasOwn(values, selected)) entries.unshift([selected, 0]);
  return [
    { value: '', label: allLabel },
    ...entries.map(([value, count]) => ({
      value,
      label: count > 0 ? `${value} (${count})` : value,
    })),
  ];
}

function relationFacetOptions(
  values: Record<string, SearchRelationFacet | number>,
  hits: SearchHit[],
  relation: 'entity' | 'book',
  selected: string | undefined,
  allLabel: string,
): { value: string; label: string }[] {
  const idsByLabel = new Map<string, string>();
  for (const hit of hits) {
    const id = relation === 'entity' ? hit.entity_id : hit.book_id;
    const label = relation === 'entity' ? hit.entity_name : hit.book_label;
    if (id && label) idsByLabel.set(label, id);
  }
  const options = Object.entries(values).map(([key, facet], index) => {
    if (typeof facet !== 'number') {
      return { value: key, label: `${facet.label} (${facet.count})` };
    }
    // Compatibility with a pre-id-facet server: show every friendly label/count, but only enable
    // it when a current hit proves the stable id. A label is never sent as an *_id filter.
    const id = idsByLabel.get(key);
    return id
      ? { value: id, label: `${key} (${facet})` }
      : {
          value: `unmapped-relation-${index}`,
          label: `${key} (${facet})`,
          disabled: true,
        };
  });
  if (selected && !options.some((option) => option.value === selected)) {
    options.unshift({ value: selected, label: selected });
  }
  return [{ value: '', label: allLabel }, ...options];
}

function formatNumber(value: number, locale: string): string {
  return new Intl.NumberFormat(locale).format(value);
}

function SearchIndexNotices({ status, locale }: { status: SearchStatusResponse; locale: string }) {
  const st = useSearchT();
  const notices = [];
  if (status.phase === 'error') {
    notices.push(
      <InlineWarning key="error" tone="error" title={st('search.state.error.title')}>
        {st('search.state.error.body')}
      </InlineWarning>,
    );
  }
  if (status.phase === 'starting' || status.phase === 'rebuilding') {
    notices.push(
      <InlineWarning key="indexing" tone="info" title={st('search.state.indexing.title')}>
        {st('search.state.indexing.body', {
          processed: formatNumber(status.processed, locale),
          total: formatNumber(status.total, locale),
        })}
      </InlineWarning>,
    );
  } else if (status.partial) {
    notices.push(
      <InlineWarning key="partial" tone="info" title={st('search.state.partial.title')}>
        {st('search.state.partial.body')}
      </InlineWarning>,
    );
  }
  if (status.phase === 'paused') {
    notices.push(
      <InlineWarning key="paused" tone="info" title={st('search.state.paused.title')}>
        {st('search.state.paused.body')}
      </InlineWarning>,
    );
  }
  if (status.stale) {
    notices.push(
      <InlineWarning key="stale" tone="warn" title={st('search.state.stale.title')}>
        {st('search.state.stale.body')}
      </InlineWarning>,
    );
  }
  if (status.content_budget_exhausted) {
    notices.push(
      <InlineWarning key="budget" tone="warn" title={st('search.state.budget.title')}>
        {status.content_budget_chars === undefined
          ? st('search.state.budget.redactedBody')
          : st('search.state.budget.body', {
              used: formatNumber(status.indexed_content_chars, locale),
              budget: formatNumber(status.content_budget_chars, locale),
            })}
      </InlineWarning>,
    );
  } else if (status.content_truncated) {
    notices.push(
      <InlineWarning key="truncated" tone="warn" title={st('search.state.truncated.title')}>
        {st('search.state.truncated.body', {
          count: formatNumber(status.truncated_document_count, locale),
        })}
      </InlineWarning>,
    );
  }
  return notices.length > 0 ? <div className="stack--tight">{notices}</div> : null;
}

function SearchResult({ hit }: { hit: SearchHit }) {
  const st = useSearchT();
  const href = searchHitRoute(hit);
  const metadata = [
    hit.entity_name ? st('search.hit.entity', { value: hit.entity_name }) : null,
    hit.book_label ? st('search.hit.book', { value: hit.book_label }) : null,
    hit.author ? st('search.hit.author', { value: hit.author }) : null,
    hit.law ? st('search.hit.law', { value: hit.law }) : null,
    hit.status ? st('search.hit.status', { value: hit.status }) : null,
  ].filter((value): value is string => value !== null);

  return (
    <article className="full-search-result">
      <div className="full-search-result__heading">
        <div className="full-search-result__title">
          <Badge tone="accent">{st(`search.kind.${hit.kind}` as SearchCopyKey)}</Badge>
          <h3>{hit.title}</h3>
        </div>
        {href ? (
          <ButtonLink
            to={href}
            variant="ghost"
            icon={<Icon.ArrowRight />}
            className="full-search-result__open"
          >
            {st('search.results.open', { title: hit.title })}
          </ButtonLink>
        ) : null}
      </div>
      {hit.snippet ? <p className="full-search-result__snippet">{hit.snippet}</p> : null}
      <div className="full-search-result__meta">
        {metadata.map((value) => (
          <span key={value}>{value}</span>
        ))}
        {hit.occurred_at ? (
          <span>
            {st('search.hit.date', { value: '' })} <DateTime value={hit.occurred_at} />
          </span>
        ) : null}
        {hit.content_truncated ? <Badge tone="warn">{st('search.hit.truncated')}</Badge> : null}
      </div>
    </article>
  );
}

export function SearchPage() {
  const st = useSearchT();
  const locale = useActiveLocale();
  const { canAny } = usePermissions();
  const canSearch = canAny('search.read');
  const [params, setParams] = useSearchParams();
  const committedQuery = optionalParam(params, 'q') ?? '';
  const [queryDraft, setQueryDraft] = useState(committedQuery);

  useEffect(() => setQueryDraft(committedQuery), [committedQuery]);

  const kindParam = params.get('kind') ?? '';
  const kinds = useMemo(() => selectedKinds(kindParam), [kindParam]);
  const queryParams = useMemo<SearchQueryParams>(
    () => ({
      q: committedQuery || undefined,
      kinds: kinds.length > 0 ? kinds : undefined,
      entity_id: optionalParam(params, 'entity_id'),
      book_id: optionalParam(params, 'book_id'),
      author: optionalParam(params, 'author'),
      law: optionalParam(params, 'law'),
      status: optionalParam(params, 'status'),
      date_from: optionalParam(params, 'date_from'),
      date_to: optionalParam(params, 'date_to'),
      limit: RESULT_PAGE_SIZE,
    }),
    [committedQuery, kinds, params],
  );
  const hasFilter = Boolean(
    kinds.length ||
    queryParams.entity_id ||
    queryParams.book_id ||
    queryParams.author ||
    queryParams.law ||
    queryParams.status ||
    queryParams.date_from ||
    queryParams.date_to,
  );
  const queryTooShort = committedQuery.length > 0 && [...committedQuery].length < 2;
  const hasCriteria = committedQuery.length > 0 || hasFilter;
  const canRun = canSearch && hasCriteria && !queryTooShort;
  const statusQuery = useSearchStatus(canSearch);
  const resultsQuery = useFullSearch(
    queryParams,
    canRun && statusQuery.isSuccess && statusQuery.data.enabled,
  );
  const pages = resultsQuery.data?.pages ?? [];
  const hits = pages.flatMap((page) => page.page.hits);
  const firstPage = pages[0]?.page;
  const facets: SearchFacets = firstPage?.facets ?? {
    kind: {},
    date: {},
    entity: {},
    book: {},
    author: {},
    law: {},
    status: {},
  };
  const index = pages.at(-1)?.index ?? statusQuery.data;

  const replaceParam = (name: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(name, value);
    else next.delete(name);
    setParams(next, { replace: true });
  };

  const toggleKind = (kind: SearchKind, checked: boolean) => {
    const nextKinds = checked
      ? SEARCH_KINDS.filter((candidate) => candidate === kind || kinds.includes(candidate))
      : kinds.filter((candidate) => candidate !== kind);
    replaceParam('kind', nextKinds.join(','));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    replaceParam('q', queryDraft.trim());
  };

  const clear = () => {
    setQueryDraft('');
    setParams(new URLSearchParams(), { replace: true });
  };

  // Fail closed without mounting result labels, facets, state copy, or requests.
  if (!canSearch) return null;

  if (statusQuery.isLoading) return <SkeletonList items={4} />;
  if (statusQuery.error) return <ErrorNote error={statusQuery.error} />;

  const author = queryParams.author;
  const law = queryParams.law;
  const resultStatus = queryParams.status;
  const entityId = queryParams.entity_id;
  const bookId = queryParams.book_id;
  const advancedActive = hasFilter;

  return (
    <section className="full-search stack" aria-label={st('search.form.aria')}>
      <form className="full-search__filters" role="search" onSubmit={submit}>
        <div className="full-search__primary">
          <Field
            label={st('search.query.label')}
            htmlFor="full-search-query"
            error={queryTooShort ? st('search.query.minimum') : undefined}
          >
            <Input
              id="full-search-query"
              type="search"
              autoComplete="off"
              value={queryDraft}
              placeholder={st('search.query.placeholder')}
              onChange={(event) => setQueryDraft(event.target.value)}
            />
          </Field>
          <Button type="submit" variant="primary" icon={<Icon.Search />}>
            {st('search.submit')}
          </Button>
          {hasCriteria || queryDraft ? (
            <IconButton
              type="button"
              icon={<Icon.Close />}
              label={st('search.clear')}
              onClick={clear}
            />
          ) : null}
        </div>

        <details
          className="full-search__advanced filter-advanced"
          open={advancedActive || undefined}
        >
          <summary>{st('search.filters.show')}</summary>
          <div className="full-search__advanced-body filter-advanced__body">
            <fieldset className="full-search__kinds">
              <legend>{st('search.filters.kinds')}</legend>
              <div className="full-search__kind-grid">
                {SEARCH_KINDS.map((kind) => (
                  <label key={kind} className="full-search__kind">
                    <input
                      type="checkbox"
                      checked={kinds.includes(kind)}
                      onChange={(event) => toggleKind(kind, event.target.checked)}
                    />
                    <span>{st(`search.kind.${kind}` as SearchCopyKey)}</span>
                    {facets.kind[kind] !== undefined ? (
                      <span className="muted">{formatNumber(facets.kind[kind], locale)}</span>
                    ) : null}
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="full-search__facet-grid">
              <Field label={st('search.filters.entity')} htmlFor="full-search-entity">
                <Select
                  id="full-search-entity"
                  value={entityId ?? ''}
                  options={relationFacetOptions(
                    facets.entity,
                    hits,
                    'entity',
                    entityId,
                    st('search.filters.all'),
                  )}
                  onChange={(event) => replaceParam('entity_id', event.target.value)}
                />
              </Field>
              <Field label={st('search.filters.book')} htmlFor="full-search-book">
                <Select
                  id="full-search-book"
                  value={bookId ?? ''}
                  options={relationFacetOptions(
                    facets.book,
                    hits,
                    'book',
                    bookId,
                    st('search.filters.all'),
                  )}
                  onChange={(event) => replaceParam('book_id', event.target.value)}
                />
              </Field>
              <Field label={st('search.filters.author')} htmlFor="full-search-author">
                <Select
                  id="full-search-author"
                  value={author ?? ''}
                  options={facetOptions(facets.author, author, st('search.filters.all'))}
                  onChange={(event) => replaceParam('author', event.target.value)}
                />
              </Field>
              <Field label={st('search.filters.law')} htmlFor="full-search-law">
                <Select
                  id="full-search-law"
                  value={law ?? ''}
                  options={facetOptions(facets.law, law, st('search.filters.all'))}
                  onChange={(event) => replaceParam('law', event.target.value)}
                />
              </Field>
              <Field label={st('search.filters.status')} htmlFor="full-search-status">
                <Select
                  id="full-search-status"
                  value={resultStatus ?? ''}
                  options={facetOptions(facets.status, resultStatus, st('search.filters.all'))}
                  onChange={(event) => replaceParam('status', event.target.value)}
                />
              </Field>
              <Field label={st('search.filters.dateFrom')} htmlFor="full-search-date-from">
                <Input
                  id="full-search-date-from"
                  type="date"
                  value={queryParams.date_from ?? ''}
                  max={queryParams.date_to}
                  onChange={(event) => replaceParam('date_from', event.target.value)}
                />
              </Field>
              <Field label={st('search.filters.dateTo')} htmlFor="full-search-date-to">
                <Input
                  id="full-search-date-to"
                  type="date"
                  value={queryParams.date_to ?? ''}
                  min={queryParams.date_from}
                  onChange={(event) => replaceParam('date_to', event.target.value)}
                />
              </Field>
            </div>
          </div>
        </details>
      </form>

      {index && !index.enabled ? (
        <InlineWarning tone="info" title={st('search.state.disabled.title')}>
          {st('search.state.disabled.body')}
        </InlineWarning>
      ) : index ? (
        <SearchIndexNotices status={index} locale={locale} />
      ) : null}

      {!hasCriteria ? (
        <EmptyState title={st('search.initial.title')}>
          <p>{st('search.initial.body')}</p>
        </EmptyState>
      ) : queryTooShort ? null : resultsQuery.isLoading ? (
        <SkeletonList items={5} />
      ) : resultsQuery.error ? (
        <ErrorNote error={resultsQuery.error} />
      ) : firstPage && firstPage.total === 0 ? (
        <EmptyState title={st('search.empty.title')}>
          <p>{st('search.empty.body')}</p>
        </EmptyState>
      ) : firstPage ? (
        <div className="full-search__results stack--tight">
          <header className="full-search__results-head">
            <div>
              <h2>{st('search.results.title')}</h2>
              <p className="muted" aria-live="polite">
                {st('search.results.count', {
                  count: formatNumber(firstPage.total, locale),
                })}
              </p>
            </div>
            <span className="muted">
              {st('search.results.loaded', { count: formatNumber(hits.length, locale) })}
            </span>
          </header>
          <div className="full-search__result-list">
            {hits.map((hit) => (
              <SearchResult key={hit.id} hit={hit} />
            ))}
          </div>
          {resultsQuery.hasNextPage ? (
            <Button
              type="button"
              className="full-search__load-more"
              disabled={resultsQuery.isFetchingNextPage}
              onClick={() => void resultsQuery.fetchNextPage()}
            >
              {resultsQuery.isFetchingNextPage
                ? st('search.results.loadingMore')
                : st('search.results.loadMore')}
            </Button>
          ) : (
            <p className="full-search__end muted">{st('search.results.end')}</p>
          )}
        </div>
      ) : null}
    </section>
  );
}
