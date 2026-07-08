/**
 * Legislação (t24, extended t55-E3) — the law surface on the Ferramentas tab.
 *
 * It hosts two complementary views behind a {@link SubNav}, deep-linked via `?leg=`:
 *  - **Texto integral** ({@link CorpusReader}, the default) — the full, searchable statute
 *    corpus: full-text search across every diploma/article, browse-by-diploma, article view,
 *    and per-article Verified/Pending authenticity, backed by the read-only corpus API (t55).
 *  - **Prateleira curada** ({@link CuratedShelf}) — the editorial highlights: curated diplomas
 *    with faithful extracts, official links, last-reviewed dates and the mini law archive (t27).
 *
 * The corpus reader is the default because it is the primary way to "check out" and text-search
 * the full law data; the curated shelf remains one click away. Each view manages its own search /
 * navigation params (`?q=`, `?diploma=`, `?artigo=`); switching view is `?leg=` and re-keys the
 * content region so it replays the enter animation.
 */
import { useSearchParams } from 'react-router-dom';
import { useT } from '../../i18n';
import { Icon, SubNav } from '../../ui';
import { CorpusReader } from './CorpusReader';
import { CuratedShelf } from './CuratedShelf';

type LegView = 'corpus' | 'prateleira';

export function LegislacaoPage() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const view: LegView = params.get('leg') === 'prateleira' ? 'prateleira' : 'corpus';

  function selectView(next: LegView) {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        // The corpus reader is the default, so it carries no `leg` param.
        if (next === 'corpus') p.delete('leg');
        else p.set('leg', next);
        return p;
      },
      { replace: true },
    );
  }

  return (
    <div className="stack--tight">
      <SubNav<LegView>
        ariaLabel={t('legislacao.subnav.aria')}
        active={view}
        onSelect={selectView}
        items={[
          { id: 'corpus', label: t('legislacao.subnav.corpus'), icon: <Icon.FileText /> },
          { id: 'prateleira', label: t('legislacao.subnav.shelf'), icon: <Icon.Scale /> },
        ]}
      />
      <div className="route-transition" key={view}>
        {view === 'prateleira' ? <CuratedShelf /> : <CorpusReader />}
      </div>
    </div>
  );
}
