/**
 * The full-text law corpus reader (t55-E3) — the prominent, searchable view of the Legislação
 * surface, hosted beside the curated {@link CuratedShelf} by {@link LegislacaoPage}.
 *
 * It surfaces the embedded statute corpus (`chancela-law`, t55) over the read-only corpus API:
 *  - **Full-text search** (`GET /v1/law/corpus/search`) — a prominent, debounced box that ranks
 *    hits with the diploma title, article label/heading and a context snippet; a hit opens the
 *    article.
 *  - **Browse by diploma** (`GET /v1/law/corpus`) — the diplomas with their article/verified/
 *    pending counts; opening one reads its full article set (`GET /v1/law/corpus/{diploma}`).
 *  - **Article view** — one article's full verbatim text + its citation.
 *
 * ## Authenticity honesty (the whole point)
 * Every diploma, article and hit is badged with its verification status. A **Verified** article
 * renders its verbatim text + a complete citation; a **Pending** article NEVER presents an
 * un-sourced body — the backend returns the loud unverified marker as its `body`, which the
 * reader renders inside an explicit "por verificar" warning, never styled as authoritative law.
 * The corpus provenance (origin, generation stamp, integrity digest, verified/pending coverage)
 * is disclosed in an "origem e autenticidade" caveat on the overview, consistent with the shelf's
 * informative-caveat pattern. The official publication in the Diário da República / EUR-Lex always
 * prevails.
 *
 * Navigation is deep-linkable: `?diploma=<id>` opens a diploma, `?diploma=<id>&artigo=<n>` an
 * article, and `?q=<text>` a search — so any view can be shared or reloaded. An old server that
 * predates the corpus API surfaces the endpoint error honestly via {@link ErrorNote}.
 */
import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useLawCorpus, useLawCorpusSearch, useLawDiploma } from '../../api/hooks';
import type {
  LawArticleView,
  LawCorpusView,
  LawDiplomaSummaryView,
  LawSearchHitView,
} from '../../api/types';
import { useT } from '../../i18n';
import type { TFunction } from '../../i18n';
import {
  Badge,
  Button,
  EmptyState,
  ErrorNote,
  Input,
  Loading,
  InlineWarning,
  abbreviateDigest,
} from '../../ui';
import { ExternalLink } from './links';

/** Verified vs Pending — visually distinct badges so authenticity is never ambiguous. */
function AuthenticityBadge({ verified }: { verified: boolean }) {
  const t = useT();
  return verified ? (
    <Badge tone="ok">{t('legislacao.corpus.badge.verified')}</Badge>
  ) : (
    <Badge tone="warn">{t('legislacao.corpus.badge.pending')}</Badge>
  );
}

/** An article's printed title: its label, plus the epígrafe when the article carries one. */
function articleTitle(label: string, heading: string): string {
  return heading.trim() ? `${label} — ${heading}` : label;
}

// --- Overview: provenance caveat + diploma browse ---------------------------------------------

function AuthenticityCaveat({ corpus }: { corpus: LawCorpusView }) {
  const t = useT();
  const origin =
    corpus.origin === 'Embedded'
      ? t('legislacao.corpus.origin.embedded')
      : t('legislacao.corpus.origin.cache');
  return (
    <InlineWarning tone="info" title={t('legislacao.corpus.authenticity.title')}>
      <p>
        {t('legislacao.corpus.authenticity.body', {
          origin,
          date: corpus.generated_at.slice(0, 10),
          digest: abbreviateDigest(corpus.digest, 8),
          verified: corpus.counts.verified,
          pending: corpus.counts.pending,
          articles: corpus.counts.articles,
        })}
      </p>
      {corpus.provenance ? (
        <p className="muted">
          {t('legislacao.corpus.provenance', {
            source: corpus.provenance.source_kind,
            date: corpus.provenance.retrieved_at.slice(0, 10),
          })}{' '}
          <ExternalLink href={corpus.provenance.source_url}>
            {corpus.provenance.source_url}
          </ExternalLink>
        </p>
      ) : null}
    </InlineWarning>
  );
}

function DiplomaRow({
  diploma,
  onOpen,
}: {
  diploma: LawDiplomaSummaryView;
  onOpen: (id: string) => void;
}) {
  const t = useT();
  const fullyVerified = diploma.pending_count === 0 && diploma.article_count > 0;
  return (
    <button
      type="button"
      className="leg-corpus__diploma"
      onClick={() => onOpen(diploma.id)}
      aria-label={t('legislacao.corpus.openDiploma', { title: diploma.title })}
    >
      <span className="leg-corpus__diploma-main">
        <span className="leg-corpus__diploma-title">{diploma.title}</span>
        <span className="leg-corpus__diploma-ref mono">{diploma.ref}</span>
      </span>
      <span className="leg-corpus__diploma-meta">
        <AuthenticityBadge verified={fullyVerified} />
        <span className="leg-corpus__diploma-counts muted">
          {t('legislacao.corpus.diploma.counts', {
            articles: diploma.article_count,
            verified: diploma.verified_count,
            pending: diploma.pending_count,
          })}
        </span>
      </span>
    </button>
  );
}

function CorpusOverview({ onOpenDiploma }: { onOpenDiploma: (id: string) => void }) {
  const t = useT();
  const corpus = useLawCorpus();

  if (corpus.isPending) return <Loading label={t('legislacao.corpus.loading')} />;
  if (corpus.error) return <ErrorNote error={corpus.error} />;
  const data = corpus.data;
  if (!data) return <ErrorNote error={new Error(t('legislacao.corpus.unavailable'))} />;

  return (
    <div className="stack--tight">
      <AuthenticityCaveat corpus={data} />
      <h3 className="leg-group__title">{t('legislacao.corpus.diplomas.title')}</h3>
      <div className="leg-corpus__diplomas">
        {data.diplomas.map((d) => (
          <DiplomaRow key={d.id} diploma={d} onOpen={onOpenDiploma} />
        ))}
      </div>
    </div>
  );
}

// --- Article rendering (shared by the diploma detail + the single-article view) ---------------

/** The full body of one article — verbatim for Verified, or the flagged marker for Pending. */
function ArticleBody({ article }: { article: LawArticleView }) {
  const t = useT();
  if (!article.verified) {
    // NEVER present a Pending article's (un-sourced) body as law: render the backend's loud
    // marker inside an explicit warning that says the verified text is not yet available.
    return (
      <InlineWarning tone="warn" title={t('legislacao.corpus.pending.title')}>
        <p className="leg-corpus__marker mono">{article.body}</p>
        <p>{t('legislacao.corpus.pending.body')}</p>
      </InlineWarning>
    );
  }
  return (
    <p className="leg-corpus__body" style={{ whiteSpace: 'pre-wrap' }}>
      {article.body}
    </p>
  );
}

/** The citation block for a Verified article — its source diploma/article + DR/EUR-Lex origin. */
function Citation({ article }: { article: LawArticleView }) {
  const t = useT();
  const s = article.source;
  return (
    <dl className="leg-corpus__citation">
      <div>
        <dt>{t('legislacao.corpus.article.source')}</dt>
        <dd>
          {s.diploma}, {s.article}
        </dd>
      </div>
      {s.dr_reference ? (
        <div>
          <dt>{t('legislacao.corpus.article.reference')}</dt>
          <dd>{s.dr_reference}</dd>
        </div>
      ) : null}
      {s.url ? (
        <div>
          <dt>{t('legislacao.corpus.article.official')}</dt>
          <dd>
            <ExternalLink href={s.url}>{s.url}</ExternalLink>
          </dd>
        </div>
      ) : null}
      {s.source_digest ? (
        <div>
          <dt>{t('legislacao.corpus.article.digest')}</dt>
          <dd className="mono">{abbreviateDigest(s.source_digest, 8)}</dd>
        </div>
      ) : null}
      {s.retrieved_at ? (
        <div>
          <dt>{t('legislacao.corpus.article.retrieved')}</dt>
          <dd>{s.retrieved_at.slice(0, 10)}</dd>
        </div>
      ) : null}
    </dl>
  );
}

function ArticleCard({
  article,
  onOpen,
}: {
  article: LawArticleView;
  onOpen: (number: string) => void;
}) {
  const t = useT();
  return (
    <article className="leg-corpus__article" id={`artigo-${article.number}`}>
      <header className="leg-corpus__article-head">
        <button
          type="button"
          className="leg-corpus__article-title"
          onClick={() => onOpen(article.number)}
          aria-label={t('legislacao.corpus.openArticle', { label: article.label })}
        >
          {articleTitle(article.label, article.heading)}
        </button>
        <AuthenticityBadge verified={article.verified} />
      </header>
      <ArticleBody article={article} />
    </article>
  );
}

// --- Diploma detail ---------------------------------------------------------------------------

function DiplomaDetail({
  diplomaId,
  onOpenArticle,
  onBack,
}: {
  diplomaId: string;
  onOpenArticle: (diplomaId: string, number: string) => void;
  onBack: () => void;
}) {
  const t = useT();
  const q = useLawDiploma(diplomaId);

  if (q.isPending) return <Loading label={t('legislacao.corpus.loading')} />;
  if (q.error) return <ErrorNote error={q.error} />;
  const d = q.data;
  if (!d) return <EmptyState title={t('legislacao.corpus.diploma.notFound')} />;

  const fullyVerified = d.pending_count === 0 && d.article_count > 0;
  return (
    <div className="stack--tight">
      <Button type="button" variant="ghost" className="leg-corpus__back" onClick={onBack}>
        {t('legislacao.corpus.back')}
      </Button>
      <header className="leg-corpus__diploma-header">
        <h3 className="panel__title">{d.title}</h3>
        <p className="leg-card__ref mono">{d.ref}</p>
        <div className="leg-card__badges">
          <AuthenticityBadge verified={fullyVerified} />
          <Badge tone="neutral">
            {t('legislacao.corpus.diploma.counts', {
              articles: d.article_count,
              verified: d.verified_count,
              pending: d.pending_count,
            })}
          </Badge>
        </div>
        <ExternalLink href={d.official_url}>{t('legislacao.officialPublication')}</ExternalLink>
      </header>
      <div className="leg-corpus__articles">
        {d.articles.map((a) => (
          <ArticleCard
            key={a.number}
            article={a}
            onOpen={(number) => onOpenArticle(d.id, number)}
          />
        ))}
      </div>
    </div>
  );
}

// --- Single-article view ----------------------------------------------------------------------

function ArticleView({
  diplomaId,
  articleNumber,
  onBackToDiploma,
}: {
  diplomaId: string;
  articleNumber: string;
  onBackToDiploma: (id: string) => void;
}) {
  const t = useT();
  const q = useLawDiploma(diplomaId);

  if (q.isPending) return <Loading label={t('legislacao.corpus.loading')} />;
  if (q.error) return <ErrorNote error={q.error} />;
  const d = q.data;
  if (!d) return <EmptyState title={t('legislacao.corpus.diploma.notFound')} />;
  const article = d.articles.find((a) => a.number === articleNumber);
  if (!article) return <EmptyState title={t('legislacao.corpus.article.notFound')} />;

  return (
    <div className="stack--tight">
      <Button
        type="button"
        variant="ghost"
        className="leg-corpus__back"
        onClick={() => onBackToDiploma(diplomaId)}
      >
        {t('legislacao.corpus.backToDiploma', { title: d.title })}
      </Button>
      <article className="leg-corpus__article leg-corpus__article--focused">
        <header className="leg-corpus__article-head">
          <div>
            <p className="leg-corpus__article-diploma muted">{d.title}</p>
            <h3 className="leg-corpus__article-title-h">
              {articleTitle(article.label, article.heading)}
            </h3>
          </div>
          <AuthenticityBadge verified={article.verified} />
        </header>
        <ArticleBody article={article} />
        {article.cross_refs && article.cross_refs.length > 0 ? (
          <p className="leg-corpus__crossrefs muted">
            {t('legislacao.corpus.crossRefs', { refs: article.cross_refs.join(', ') })}
          </p>
        ) : null}
        <Citation article={article} />
      </article>
    </div>
  );
}

// --- Search -----------------------------------------------------------------------------------

function SearchHit({
  hit,
  onOpen,
}: {
  hit: LawSearchHitView;
  onOpen: (diplomaId: string, number: string) => void;
}) {
  const t = useT();
  return (
    <button
      type="button"
      className="leg-corpus__hit"
      onClick={() => onOpen(hit.diploma_id, hit.number)}
      aria-label={t('legislacao.corpus.openArticle', { label: hit.label })}
    >
      <span className="leg-corpus__hit-head">
        <span className="leg-corpus__hit-title">{articleTitle(hit.label, hit.heading)}</span>
        <AuthenticityBadge verified={hit.verified} />
      </span>
      <span className="leg-corpus__hit-diploma muted">{hit.diploma_title}</span>
      <span className="leg-corpus__hit-snippet">{hit.snippet}</span>
    </button>
  );
}

function SearchResults({
  term,
  onOpen,
}: {
  term: string;
  onOpen: (diplomaId: string, number: string) => void;
}) {
  const t = useT();
  const q = useLawCorpusSearch(term);

  if (q.isPending) return <Loading label={t('legislacao.corpus.loading')} />;
  if (q.error) return <ErrorNote error={q.error} />;
  const data = q.data;
  if (!data || data.results.length === 0) {
    return (
      <EmptyState title={t('legislacao.corpus.search.emptyTitle')}>
        <p>{t('legislacao.corpus.search.empty', { term })}</p>
      </EmptyState>
    );
  }
  return (
    <div className="stack--tight">
      <p className="leg-search__count" role="status" aria-live="polite">
        {t('legislacao.corpus.search.count', { count: data.count })}
      </p>
      <div className="leg-corpus__hits">
        {data.results.map((h) => (
          <SearchHit key={`${h.diploma_id}:${h.number}`} hit={h} onOpen={onOpen} />
        ))}
      </div>
    </div>
  );
}

// --- The reader ------------------------------------------------------------------------------

export function CorpusReader() {
  const t: TFunction = useT();
  const [params, setParams] = useSearchParams();

  const diplomaId = params.get('diploma') ?? '';
  const articleNumber = params.get('artigo') ?? '';
  const initialQuery = params.get('q') ?? '';
  const [term, setTerm] = useState(initialQuery);
  const [debounced, setDebounced] = useState(initialQuery);

  // Debounce the search box, mirroring the CAE explorer / curated-shelf idiom. The query is
  // seeded from `?q=` on mount (so a search is deep-linkable IN) but kept as local state —
  // it is deliberately NOT written back to the URL, so it never races the diploma/article
  // navigation params below (react-router coalesces same-tick `setParams` calls).
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(term), 200);
    return () => window.clearTimeout(timer);
  }, [term]);

  // Leaving search mode on a navigation click: clear both the input and the debounced value so
  // the view switches to the selection immediately (not after the debounce window elapses).
  function leaveSearch() {
    setTerm('');
    setDebounced('');
  }

  function openDiploma(id: string) {
    leaveSearch();
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        p.set('diploma', id);
        p.delete('artigo');
        p.delete('q');
        return p;
      },
      { replace: true },
    );
  }

  function openArticle(id: string, number: string) {
    leaveSearch();
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        p.set('diploma', id);
        p.set('artigo', number);
        p.delete('q');
        return p;
      },
      { replace: true },
    );
  }

  function backToCorpus() {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        p.delete('diploma');
        p.delete('artigo');
        p.delete('q');
        return p;
      },
      { replace: true },
    );
  }

  const query = debounced.trim();
  const searching = query.length > 0;

  return (
    <section className="panel leg-corpus">
      <header className="panel__head">
        <h3 className="panel__title">{t('legislacao.corpus.title')}</h3>
      </header>
      <div className="panel__body stack--tight">
        <p className="leg-corpus__lede muted">{t('legislacao.corpus.lede')}</p>

        <div className="leg-search">
          <Input
            type="search"
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            placeholder={t('legislacao.corpus.search.placeholder')}
            aria-label={t('legislacao.corpus.search.aria')}
            autoComplete="off"
          />
          {searching ? (
            <div className="leg-search__status">
              <Button
                type="button"
                variant="ghost"
                className="leg-search__clear"
                onClick={() => setTerm('')}
              >
                {t('legislacao.corpus.search.clear')}
              </Button>
            </div>
          ) : null}
        </div>

        {searching ? (
          <SearchResults term={query} onOpen={openArticle} />
        ) : diplomaId && articleNumber ? (
          <ArticleView
            diplomaId={diplomaId}
            articleNumber={articleNumber}
            onBackToDiploma={openDiploma}
          />
        ) : diplomaId ? (
          <DiplomaDetail diplomaId={diplomaId} onOpenArticle={openArticle} onBack={backToCorpus} />
        ) : (
          <CorpusOverview onOpenDiploma={openDiploma} />
        )}
      </div>
    </section>
  );
}
