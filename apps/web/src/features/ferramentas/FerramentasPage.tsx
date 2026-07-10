/**
 * Ferramentas (t22-web item 3) — the tools surface reached from the fixed tab bar.
 *
 * A sub-navigation (segmented control) switches between three consultation surfaces:
 *  - **Catálogo CAE** (default) — the CAE explorer (search + revision switch + hierarchy
 *    drill-down) and the catalog's state + "Atualizar catálogo" refresh, relocated here
 *    from the former standalone /cae page, which now redirects in.
 *  - **Legislação** (t24) — a curated law shelf: the diplomas that ground the product,
 *    each with a faithful extract, official links and a last-reviewed date.
 *  - **Validador PDF** — local technical PDF/PAdES evidence validation for an uploaded
 *    PDF, backed by `POST /v1/signature/pdf/validate`.
 *  - **Lista de confiança** — the read-only TSL trust catalog/status surface for
 *    checking the parsed scheme, provider and service trust metadata.
 *  - **Assinatura externa** — operational tracking for redacted external-signer invites
 *    and token-held public envelopes.
 *
 * Each tool is a deep-linkable sub-tab: the active one lives in the URL (`?tool=...`);
 * its absence means the CAE surface, so `/cae` deep links and the CAE search flow open
 * unchanged. The CAE explorer's own `?code=`/`?rev=` params are independent and preserved
 * across switches. The `SECTIONS` list is the single extension point for future tools.
 */
import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useActiveLocale, useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { Icon, PageHeader } from '../../ui';
import { CaeExplorer } from '../cae/CaeExplorer';
import { CaeCatalogPanel } from '../cae/CaeCatalogPanel';
import { LegislacaoPage } from '../legislacao/LegislacaoPage';
import { PdfSignatureValidatorPanel } from './PdfSignatureValidatorPanel';
import { TrustCatalogPage } from './TrustCatalogPage';
import { ExternalSigningWorkflowsPage } from './ExternalSigningWorkflowsPage';

type FerramentasSection = 'cae' | 'legislacao' | 'pdf' | 'trust' | 'external-signing';

const SECTIONS: { id: FerramentasSection; label: MessageKey; icon: ReactNode }[] = [
  { id: 'cae', label: 'tools.section.cae', icon: <Icon.Layers /> },
  { id: 'legislacao', label: 'tools.section.legislacao', icon: <Icon.Scale /> },
  { id: 'pdf', label: 'tools.section.pdfValidator', icon: <Icon.FileText /> },
  { id: 'trust', label: 'tools.section.trust', icon: <Icon.Seal /> },
  { id: 'external-signing', label: 'tools.section.externalSigning', icon: <Icon.PenNib /> },
];

export function FerramentasPage() {
  const t = useT();
  const locale = useActiveLocale();
  const [params, setParams] = useSearchParams();
  const section: FerramentasSection =
    params.get('tool') === 'legislacao'
      ? 'legislacao'
      : params.get('tool') === 'pdf'
        ? 'pdf'
        : params.get('tool') === 'trust'
          ? 'trust'
          : params.get('tool') === 'external-signing'
            ? 'external-signing'
            : 'cae';

  // A gilt indicator that glides to the active sub-tab (consistent with the top bar's
  // active-tab indicator). Measured from the active button so it works with the two
  // labels' differing widths and re-measures on locale change / resize; the CSS
  // transition does the sliding and collapses under prefers-reduced-motion.
  const navRef = useRef<HTMLDivElement>(null);
  const btnRefs = useRef<Record<FerramentasSection, HTMLButtonElement | null>>({
    cae: null,
    legislacao: null,
    pdf: null,
    trust: null,
    'external-signing': null,
  });
  const [indicator, setIndicator] = useState<{
    left: number;
    top: number;
    width: number;
    height: number;
  } | null>(null);

  useLayoutEffect(() => {
    const measure = () => {
      const btn = btnRefs.current[section];
      if (!btn) return;
      const next = {
        left: btn.offsetLeft,
        top: btn.offsetTop,
        width: btn.offsetWidth,
        height: btn.offsetHeight,
      };
      // Only update on a real geometry change — returning the same object ref keeps this
      // from looping (the effect itself re-runs on section/locale/resize, not on the state
      // it sets). `locale` is a stable tag; re-measure when the label widths change with it.
      setIndicator((prev) =>
        prev &&
        prev.left === next.left &&
        prev.top === next.top &&
        prev.width === next.width &&
        prev.height === next.height
          ? prev
          : next,
      );
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [section, locale]);

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
      <PageHeader crumbs={t('tools.crumbs')} title={t('tools.title')}>
        <div
          className="ferramentas-subnav"
          role="group"
          aria-label={t('tools.subnav.aria')}
          ref={navRef}
        >
          <span
            className="ferramentas-subnav__indicator"
            aria-hidden="true"
            style={
              indicator
                ? {
                    transform: `translateX(${indicator.left}px)`,
                    top: `${indicator.top}px`,
                    width: `${indicator.width}px`,
                    height: `${indicator.height}px`,
                  }
                : { opacity: 0 }
            }
          />
          {SECTIONS.map((s) => (
            <button
              key={s.id}
              ref={(el) => {
                btnRefs.current[s.id] = el;
              }}
              type="button"
              className={
                s.id === section ? 'ferramentas-subnav__btn is-active' : 'ferramentas-subnav__btn'
              }
              aria-pressed={s.id === section}
              onClick={() => selectSection(s.id)}
            >
              <span className="ferramentas-subnav__icon" aria-hidden="true">
                {s.icon}
              </span>
              {t(s.label)}
            </button>
          ))}
        </div>
      </PageHeader>

      {/* The content region replays the route-enter animation when the sub-tab changes.
          Keying on `section` (the `tool` param) means switching tool re-animates, while
          the CAE explorer's own `?code=`/`?rev=` and Legislação's `?q=` param changes do
          NOT re-key (no distracting replay). Reduced-motion collapses the animation. */}
      <div className="route-transition" key={section} data-anim-key={section}>
        {section === 'trust' ? (
          <TrustCatalogPage />
        ) : section === 'pdf' ? (
          <PdfSignatureValidatorPanel />
        ) : section === 'external-signing' ? (
          <ExternalSigningWorkflowsPage />
        ) : section === 'legislacao' ? (
          <LegislacaoPage />
        ) : (
          <div className="stack">
            <CaeExplorer />
            <CaeCatalogPanel />
          </div>
        )}
      </div>
    </div>
  );
}
