/**
 * Ferramentas (t22-web item 3) — the tools surface reached from the fixed tab bar.
 *
 * A sub-navigation (segmented control) switches between two consultation surfaces:
 *  - **Catálogo CAE** (default) — the CAE explorer (search + revision switch + hierarchy
 *    drill-down) and the catalog's state + "Atualizar catálogo" refresh, relocated here
 *    from the former standalone /cae page, which now redirects in.
 *  - **Legislação** (t24) — a curated law shelf: the diplomas that ground the product,
 *    each with a faithful extract, official links and a last-reviewed date.
 *
 * Each tool is a deep-linkable sub-tab: the active one lives in the URL (`?tool=legislacao`);
 * its absence means the CAE surface, so `/cae` deep links and the CAE search flow open
 * unchanged. The CAE explorer's own `?code=`/`?rev=` params are independent and preserved
 * across switches. The `SECTIONS` list is the single extension point for future tools.
 */
import { useSearchParams } from 'react-router-dom';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { PageHeader } from '../../ui';
import { CaeExplorer } from '../cae/CaeExplorer';
import { CaeCatalogPanel } from '../cae/CaeCatalogPanel';
import { LegislacaoPage } from '../legislacao/LegislacaoPage';

type FerramentasSection = 'cae' | 'legislacao';

const SECTIONS: { id: FerramentasSection; label: MessageKey }[] = [
  { id: 'cae', label: 'tools.section.cae' },
  { id: 'legislacao', label: 'tools.section.legislacao' },
];

export function FerramentasPage() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const section: FerramentasSection = params.get('tool') === 'legislacao' ? 'legislacao' : 'cae';

  function selectSection(next: FerramentasSection) {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        // The CAE surface is the default, so it carries no `tool` param (keeps /cae and
        // the smoke flow landing straight on the explorer).
        if (next === 'cae') p.delete('tool');
        else p.set('tool', next);
        return p;
      },
      { replace: true },
    );
  }

  return (
    <div className="stack">
      <PageHeader crumbs={t('tools.crumbs')} title={t('tools.title')} lede={t('tools.lede')}>
        <div className="ferramentas-subnav" role="group" aria-label={t('tools.subnav.aria')}>
          {SECTIONS.map((s) => (
            <button
              key={s.id}
              type="button"
              className={
                s.id === section ? 'ferramentas-subnav__btn is-active' : 'ferramentas-subnav__btn'
              }
              aria-pressed={s.id === section}
              onClick={() => selectSection(s.id)}
            >
              {t(s.label)}
            </button>
          ))}
        </div>
      </PageHeader>

      {section === 'legislacao' ? (
        <LegislacaoPage />
      ) : (
        <>
          <CaeExplorer />
          <CaeCatalogPanel />
        </>
      )}
    </div>
  );
}
