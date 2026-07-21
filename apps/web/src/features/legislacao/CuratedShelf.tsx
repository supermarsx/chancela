/**
 * The curated Legislação shelf (t24, archive-aware t27) — the editorial highlights view of
 * the Legislação surface, one of the two sub-tabs {@link LegislacaoPage} hosts (beside the
 * full-text {@link CorpusReader}).
 *
 * Renders the {@link DIPLOMAS} inventory grouped by theme. Each diploma is an editorial
 * card: title + reference, a why-it-matters note, the extract (a quotation when verbatim,
 * or flagged "resumo" when described), badges (amendment + last-reviewed) and actions.
 *
 * ## Search
 * A debounced, accent-and-case-folded search field (mirroring the CAE explorer idiom)
 * filters the cards live across each diploma's title, reference, why-note and extract via
 * {@link searchDiplomas}. The match count and a clear affordance appear while searching; an
 * empty theme is hidden and a no-match state is shown when nothing matches. The committed
 * query is deep-linkable in the tool's search params (`?q=`, alongside `?tool=legislacao`).
 *
 * ## Mini law archive (t27)
 * When the running server exposes the law store (`GET /v1/law` — feature-detected via
 * {@link useLawArchive}), each diploma with an official PDF gains archive actions:
 *  - not stored → **Guardar PDF** (downloads + digest-pins the official PDF locally) and a
 *    link to the official PDF;
 *  - stored → a **Guardado** badge (digest + date) and **Abrir PDF** served from the local
 *    store (`GET /v1/law/{id}/pdf`).
 * When the server predates t27, the archive is simply absent and every card falls back to
 * links-only (official page + official PDF), so the shelf never breaks on an old server.
 *
 * The t27 manifest (FROZEN §law-v1) is its own curation of 9 diplomas keyed by the server's
 * ids, of which only the two CAE diplomas are archivable (pinned `pdf_url`). Our display
 * shelf is 16 finer-grained entries; we match the manifest by id and offer archive actions
 * only where a matching, archivable server entry exists — see {@link PdfActions}. Aligning
 * the two id schemes (our per-article ids vs the server's per-diploma ids) is a future
 * t27-web concern, not this seam's.
 *
 * External (official) links open in the user's browser via {@link openExternal}; the local
 * stored-PDF link is an app-origin path served by the embedded server.
 */
import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ApiError, lawPdfPath } from '../../api/client';
import { useFetchLawPdf, useLawArchive, type LawArchiveState } from '../../api/hooks';
import { useT } from '../../i18n';
import { formatDate } from '../../format';
import {
  Badge,
  Button,
  DateTime,
  EmptyState,
  Input,
  abbreviateDigest,
  useToast,
} from '../../ui';
import { ExternalLink } from './links';
import {
  DIPLOMAS,
  LEGISLACAO_TEMAS,
  REVIEWED_ON,
  diplomasByTema,
  searchDiplomas,
  type Diploma,
} from './diplomas';

/**
 * The archive-aware PDF actions for one diploma (Guardar / Abrir / official PDF link).
 *
 * The local archive (t27) is keyed by the server's own diploma ids, which are coarser than
 * our display ids — so archive actions are offered ONLY when a matching manifest entry
 * exists AND it is archivable (`pdf_url` non-null, i.e. the server can actually fetch it).
 * Everywhere else the card is links-only: an id we can't map, or a diploma the server holds
 * without a pinned PDF, keeps just the official-PDF link. (The id-scheme reconciliation is
 * a future t27-web concern — see this file's header / the t24 log.)
 */
function PdfActions({
  diploma,
  archive,
}: {
  diploma: Diploma;
  archive: LawArchiveState | undefined;
}) {
  const t = useT();
  const toast = useToast();
  const store = useFetchLawPdf();

  const available = archive?.available === true;
  const entry = available ? archive.entries.get(diploma.id) : undefined;
  const stored = entry?.stored === true;
  // Only offer to store when the server knows this id AND has a pinned PDF to fetch.
  const canStore = !!entry && entry.pdf_url !== null && !stored;
  // The external "official PDF" link: our curated URL, else the server's pinned one.
  const officialPdf = diploma.pdfUrl ?? entry?.pdf_url ?? null;

  if (stored) {
    // Served from the local store — an app-origin path, not routed through openExternal.
    return (
      <a
        className="leg-link"
        href={lawPdfPath(diploma.id)}
        target="_blank"
        rel="noreferrer noopener"
      >
        {t('legislacao.pdf.open')}
      </a>
    );
  }

  if (!canStore && !officialPdf) return null;

  // Surface the server's friendly message (409 not-archivable / 422 no data dir / 502).
  const storeError = store.error
    ? store.error instanceof ApiError
      ? store.error.message
      : t('legislacao.pdf.storeError')
    : null;

  return (
    <>
      {canStore ? (
        <Button
          type="button"
          variant="ghost"
          className="leg-store-btn"
          disabled={store.isPending}
          onClick={() =>
            store.mutate(diploma.id, {
              // R7: the inline storeError note (role=alert) stays for the 409/422/502 detail.
              onSuccess: () => toast.success(t('toast.law.stored')),
              onError: (e) => toast.error(e),
            })
          }
        >
          {store.isPending ? t('legislacao.pdf.saving') : t('legislacao.pdf.save')}
        </Button>
      ) : null}
      {officialPdf ? (
        <ExternalLink href={officialPdf}>{t('legislacao.pdf.official')}</ExternalLink>
      ) : null}
      {storeError ? (
        <span className="leg-store-error" role="alert">
          {storeError}
        </span>
      ) : null}
    </>
  );
}

function DiplomaCard({
  diploma,
  archive,
}: {
  diploma: Diploma;
  archive: LawArchiveState | undefined;
}) {
  const t = useT();
  const isQuote = diploma.extractKind === 'quote';
  const available = archive?.available === true;
  const entry = available ? archive.entries.get(diploma.id) : undefined;
  const stored = entry?.stored === true;

  return (
    <article className="leg-card">
      <header className="leg-card__head">
        <h4 className="leg-card__title">{diploma.title}</h4>
        <p className="leg-card__ref mono">{diploma.ref}</p>
      </header>

      <p className="leg-card__why">{diploma.why}</p>

      {isQuote ? (
        <blockquote className="leg-card__quote">{diploma.extract}</blockquote>
      ) : (
        <div className="leg-card__resumo">
          <span className="leg-card__resumo-tag">{t('legislacao.resumoTag')}</span>
          <p className="leg-card__resumo-text">{diploma.extract}</p>
        </div>
      )}

      <footer className="leg-card__foot">
        <div className="leg-card__badges">
          {diploma.lastAmended ? (
            <Badge tone="accent">
              {t('legislacao.amendedBy', { amendment: diploma.lastAmended })}
            </Badge>
          ) : null}
          <Badge tone="neutral">
            {t('legislacao.reviewedOn', { date: formatDate(diploma.reviewedOn) })}
          </Badge>
          {stored ? (
            <Badge tone="ok">
              {t('legislacao.storedBadge')}
              {entry?.stored_digest ? ` · ${abbreviateDigest(entry.stored_digest, 6)}` : ''}
              {entry?.retrieved_at ? (
                <>
                  {' · '}
                  <DateTime value={entry.retrieved_at} />
                </>
              ) : null}
            </Badge>
          ) : null}
        </div>
        <div className="leg-card__links">
          <ExternalLink href={diploma.officialUrl}>
            {t('legislacao.officialPublication')}
          </ExternalLink>
          <PdfActions diploma={diploma} archive={archive} />
        </div>
      </footer>
    </article>
  );
}

export function CuratedShelf() {
  const t = useT();
  const archive = useLawArchive();
  const [params, setParams] = useSearchParams();

  const initialQuery = params.get('q') ?? '';
  const [term, setTerm] = useState(initialQuery);
  const [debounced, setDebounced] = useState(initialQuery);

  // Debounce the live filter, mirroring the CAE explorer's search idiom.
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(term), 180);
    return () => window.clearTimeout(timer);
  }, [term]);

  // Reflect the committed query in the URL (?q=), so a search is deep-linkable alongside
  // ?tool=legislacao. Replace-history so typing does not flood the Back stack; the CAE
  // explorer's own ?code=/?rev= params are preserved (we compose from the previous params).
  useEffect(() => {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        const q = debounced.trim();
        if (q) p.set('q', q);
        else p.delete('q');
        return p;
      },
      { replace: true },
    );
  }, [debounced, setParams]);

  const query = debounced.trim();
  const active = query.length > 0;
  const matches = active ? searchDiplomas(query) : DIPLOMAS;
  const matchIds = active ? new Set(matches.map((d) => d.id)) : null;

  return (
    <section className="panel leg-shelf">
      <header className="panel__head">
        <h3 className="panel__title">{t('legislacao.title')}</h3>
      </header>
      <div className="panel__body stack--tight">
        <p className="leg-caveat" role="note">
          {t('legislacao.caveat', { date: REVIEWED_ON })}
        </p>

        <div className="leg-search">
          <Input
            type="search"
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            placeholder={t('legislacao.search.placeholder')}
            aria-label={t('legislacao.search.aria')}
            autoComplete="off"
          />
          {active ? (
            <div className="leg-search__status">
              <span className="leg-search__count" role="status" aria-live="polite">
                {t('legislacao.search.count', { count: matches.length, total: DIPLOMAS.length })}
              </span>
              <Button
                type="button"
                variant="ghost"
                className="leg-search__clear"
                onClick={() => setTerm('')}
              >
                {t('legislacao.search.clear')}
              </Button>
            </div>
          ) : null}
        </div>

        {active && matches.length === 0 ? (
          <EmptyState title={t('legislacao.search.empty.title')}>
            <p>{t('legislacao.search.empty.body', { term: query })}</p>
          </EmptyState>
        ) : (
          LEGISLACAO_TEMAS.map((tema) => {
            const items = diplomasByTema(tema.id).filter((d) => !matchIds || matchIds.has(d.id));
            if (items.length === 0) return null;
            return (
              <section key={tema.id} className="leg-group" aria-label={tema.label}>
                <h3 className="leg-group__title">{tema.label}</h3>
                <div className="leg-group__cards">
                  {items.map((d) => (
                    <DiplomaCard key={d.id} diploma={d} archive={archive.data} />
                  ))}
                </div>
              </section>
            );
          })
        )}
      </div>
    </section>
  );
}
