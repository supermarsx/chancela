/**
 * Legislação (t24, extended t55-E3) — the law surface on the Tools tab.
 *
 * It hosts two complementary views behind a {@link SubNav}, deep-linked as a path segment
 * (`/tools/legislation/shelf`):
 *  - **Texto integral** ({@link CorpusReader}, the default) — the full, searchable statute
 *    corpus: full-text search across every diploma/article, browse-by-diploma, article view,
 *    and per-article Verified/Pending authenticity, backed by the read-only corpus API (t55).
 *  - **Prateleira curada** ({@link CuratedShelf}) — the editorial highlights: curated diplomas
 *    with faithful extracts, official links, last-reviewed dates and the mini law archive (t27).
 *
 * The corpus reader is the default because it is the primary way to "check out" and text-search
 * the full law data; the curated shelf remains one click away. Each view manages its own search /
 * navigation params (`?q=`, `?diploma=`, `?artigo=`) — those describe what you are searching
 * for, not which view you are in, so they stay in the query; switching view is a path segment
 * and re-keys the content region so it replays the enter animation.
 */
import { useT } from '../../i18n';
import { Icon, SubNav } from '../../ui';
import { useSectionNav } from '../../app/navPath';
import { CorpusReader } from './CorpusReader';
import { CuratedShelf } from './CuratedShelf';

type LegView = 'corpus' | 'shelf';

export function LegislationPage() {
  const t = useT();
  // Second level under `/tools/legislation`; the corpus reader is the default, so it
  // carries no segment of its own.
  const { section: view, select: selectView } = useSectionNav<LegView>({
    base: '/tools/legislation',
    parse: (raw) => (raw === 'shelf' ? 'shelf' : 'corpus'),
    fallback: 'corpus',
    replace: true,
  });

  return (
    <div className="stack--tight">
      <SubNav<LegView>
        ariaLabel={t('legislacao.subnav.aria')}
        active={view}
        onSelect={selectView}
        items={[
          { id: 'corpus', label: t('legislacao.subnav.corpus'), icon: <Icon.FileText /> },
          { id: 'shelf', label: t('legislacao.subnav.shelf'), icon: <Icon.Scale /> },
        ]}
      />
      <div className="route-transition" key={view}>
        {view === 'shelf' ? <CuratedShelf /> : <CorpusReader />}
      </div>
    </div>
  );
}
