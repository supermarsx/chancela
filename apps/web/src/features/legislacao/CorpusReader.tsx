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
import {
  useLawCorpus,
  useLawCorpusSearch,
  useLawDiploma,
  useResolveLawCitations,
} from '../../api/hooks';
import type {
  LawArticleView,
  LawCitationView,
  LawCorpusView,
  LawDiplomaSummaryView,
  LawSearchHitView,
  LawVerification,
} from '../../api/types';
import { useT } from '../../i18n';
import type { TFunction } from '../../i18n';
import {
  Badge,
  Button,
  EmptyState,
  ErrorNote,
  FieldHelp,
  Input,
  Loading,
  InlineWarning,
  Icon,
  abbreviateDigest,
  useToast,
} from '../../ui';
import { ExternalLink } from './links';

/**
 * Verified / automated-review / Pending — three visually distinct badges so authenticity is never
 * ambiguous. Pass `verification` for a per-article/hit tier (the honest three-state badge); pass
 * `verified` for an aggregate (whole-diploma) coverage badge that only knows human-verified vs not.
 *
 * The `automated_review` tier is its OWN thing: authentic vendored statutory text that was reviewed
 * by an AUTOMATED process and is NOT human-legally-approved. It gets an info-toned badge (never the
 * green human-verified badge, never the loud Pending warning) plus a "?" help affordance carrying
 * the honest caveat — the API's `review_note` when present, else an i18n fallback.
 */
function AuthenticityBadge({
  verification,
  verified,
  reviewNote,
}: {
  verification?: LawVerification;
  verified?: boolean;
  reviewNote?: string | null;
}) {
  const t = useT();
  if (verification === 'automated_review') {
    return (
      <span className="leg-corpus__badge-help">
        <Badge tone="info">{t('legislacao.corpus.badge.automatedReview')}</Badge>
        <FieldHelp text={reviewNote?.trim() || t('legislacao.corpus.badge.automatedReviewHelp')} />
      </span>
    );
  }
  const isVerified = verification !== undefined ? verification === 'Verified' : Boolean(verified);
  return isVerified ? (
    <Badge tone="ok">{t('legislacao.corpus.badge.verified')}</Badge>
  ) : (
    <Badge tone="warn">{t('legislacao.corpus.badge.pending')}</Badge>
  );
}

/** An article's printed title: its label, plus the epígrafe when the article carries one. */
function articleTitle(label: string, heading: string): string {
  return heading.trim() ? `${label} — ${heading}` : label;
}

function citationKey(citation: LawCitationView): string {
  return `${citation.source_id}:${citation.article}`;
}

function formatCitationLine(citation: LawCitationView, t: TFunction): string {
  const state =
    citation.verification === 'Verified'
      ? t('legislacao.corpus.badge.verified')
      : citation.verification === 'automated_review'
        ? t('legislacao.corpus.badge.automatedReview')
        : t('legislacao.citations.pendingState');
  const source = citation.source_url ? ` — ${citation.source_url}` : '';
  return `- ${citation.citation} [${state}]${source}`;
}

function formatCitationBlock(citations: LawCitationView[], notice: string, t: TFunction): string {
  return [
    t('legislacao.citations.copyHeading'),
    notice,
    ...citations.map((citation) => formatCitationLine(citation, t)),
  ].join('\n');
}

function CitationShelf({
  citations,
  notice,
  onCopy,
  onClear,
}: {
  citations: LawCitationView[];
  notice: string;
  onCopy: () => void;
  onClear: () => void;
}) {
  const t = useT();

  return (
    <aside className="leg-citations" aria-label={t('legislacao.citations.title')}>
      <div className="leg-citations__head">
        <h3 className="leg-citations__title">{t('legislacao.citations.title')}</h3>
        <div className="leg-citations__actions">
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Copy />}
            disabled={citations.length === 0}
            onClick={onCopy}
          >
            {t('legislacao.citations.copy')}
          </Button>
          <Button type="button" variant="ghost" disabled={citations.length === 0} onClick={onClear}>
            {t('legislacao.citations.clear')}
          </Button>
        </div>
      </div>
      <p className="leg-citations__notice muted">{notice}</p>
      {citations.length === 0 ? (
        <p className="leg-citations__empty muted">{t('legislacao.citations.empty')}</p>
      ) : (
        <ul className="leg-citations__list">
          {citations.map((citation) => (
            <li key={citationKey(citation)} className="leg-citations__item">
              <span className="leg-citations__text mono">{citation.citation}</span>
              <AuthenticityBadge verification={citation.verification} />
              {citation.verification === 'Pending' ? (
                <span className="muted">{t('legislacao.citations.pendingNote')}</span>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </aside>
  );
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

/**
 * The full body of one article — verbatim text for a Verified OR automated-review article (both
 * carry genuine statutory text; the tier badge + tooltip disclose that automated-review text is
 * not yet human-legally-approved), or the flagged marker only for a Pending article.
 */
function ArticleBody({ article }: { article: LawArticleView }) {
  const t = useT();
  if (article.verification === 'Pending') {
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
  onPin,
  pinPending,
}: {
  article: LawArticleView;
  onOpen: (number: string) => void;
  onPin: (article: LawArticleView) => void;
  pinPending: boolean;
}) {
  const t = useT();
  return (
    <article className="leg-corpus__article" id={`artigo-${article.number}`}>
      <header className="leg-corpus__article-head">
        <button
          type="button"
          className="leg-corpus__article-title"
          onClick={() => onOpen(article.number)}
          aria-label={t('legislacao.corpus.openArticle', {
            label: articleTitle(article.label, article.heading),
          })}
        >
          {articleTitle(article.label, article.heading)}
        </button>
        <span className="leg-corpus__article-actions">
          <AuthenticityBadge
            verification={article.verification}
            reviewNote={article.source.review_note}
          />
          <Button
            type="button"
            variant="ghost"
            className="leg-citation-pin"
            icon={<Icon.Plus />}
            disabled={pinPending}
            onClick={() => onPin(article)}
          >
            {t('legislacao.citations.pin')}
          </Button>
        </span>
      </header>
      <ArticleBody article={article} />
    </article>
  );
}

// --- Diploma detail ---------------------------------------------------------------------------

function DiplomaDetail({
  diplomaId,
  onOpenArticle,
  onPinArticle,
  pinPending,
  onBack,
}: {
  diplomaId: string;
  onOpenArticle: (diplomaId: string, number: string) => void;
  onPinArticle: (article: LawArticleView) => void;
  pinPending: boolean;
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
            onPin={onPinArticle}
            pinPending={pinPending}
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
  onPinArticle,
  pinPending,
  onBackToDiploma,
}: {
  diplomaId: string;
  articleNumber: string;
  onPinArticle: (article: LawArticleView) => void;
  pinPending: boolean;
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
          <span className="leg-corpus__article-actions">
            <AuthenticityBadge
              verification={article.verification}
              reviewNote={article.source.review_note}
            />
            <Button
              type="button"
              variant="ghost"
              className="leg-citation-pin"
              icon={<Icon.Plus />}
              disabled={pinPending}
              onClick={() => onPinArticle(article)}
            >
              {t('legislacao.citations.pin')}
            </Button>
          </span>
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
      aria-label={t('legislacao.corpus.openArticle', {
        label: articleTitle(hit.label, hit.heading),
      })}
    >
      <span className="leg-corpus__hit-head">
        <span className="leg-corpus__hit-title">{articleTitle(hit.label, hit.heading)}</span>
        <AuthenticityBadge verification={hit.verification} />
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
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const resolver = useResolveLawCitations();

  const diplomaId = params.get('diploma') ?? '';
  const articleNumber = params.get('artigo') ?? '';
  const initialQuery = params.get('q') ?? '';
  const [term, setTerm] = useState(initialQuery);
  const [debounced, setDebounced] = useState(initialQuery);
  const [citations, setCitations] = useState<LawCitationView[]>([]);
  const [citationNotice, setCitationNotice] = useState(t('legislacao.citations.notice'));

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

  function pinArticle(article: LawArticleView) {
    resolver.mutate(
      { references: [{ diploma_id: article.diploma_id, article: article.number }] },
      {
        onSuccess: (report) => {
          setCitationNotice(report.legal_notice || t('legislacao.citations.notice'));
          setCitations((current) => {
            const next = [...current];
            for (const citation of report.citations) {
              if (!next.some((item) => citationKey(item) === citationKey(citation))) {
                next.push(citation);
              }
            }
            return next;
          });
          toast.success(t('legislacao.citations.pinned'));
        },
        onError: (err) => toast.error(err),
      },
    );
  }

  async function copyCitations() {
    if (!navigator.clipboard) {
      toast.error(t('legislacao.citations.copyUnsupported'));
      return;
    }
    try {
      await navigator.clipboard.writeText(formatCitationBlock(citations, citationNotice, t));
      toast.success(t('legislacao.citations.copied'));
    } catch (err) {
      toast.error(err);
    }
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
        <CitationShelf
          citations={citations}
          notice={citationNotice}
          onCopy={() => void copyCitations()}
          onClear={() => setCitations([])}
        />

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
            onPinArticle={pinArticle}
            pinPending={resolver.isPending}
            onBackToDiploma={openDiploma}
          />
        ) : diplomaId ? (
          <DiplomaDetail
            diplomaId={diplomaId}
            onOpenArticle={openArticle}
            onPinArticle={pinArticle}
            pinPending={resolver.isPending}
            onBack={backToCorpus}
          />
        ) : (
          <CorpusOverview onOpenDiploma={openDiploma} />
        )}
      </div>
    </section>
  );
}
