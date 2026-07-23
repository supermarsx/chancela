/**
 * Tools (t22-web item 3) — the tools surface reached from the fixed tab bar.
 *
 * A sub-navigation (segmented control) switches between three consultation surfaces:
 *  - **Catálogo CAE** (default) — the CAE explorer (search + revision switch + hierarchy
 *    drill-down) and the catalog's state + "Atualizar catálogo" refresh, relocated here
 *    from the former standalone /cae page, which now redirects in.
 *  - **Legislação** (t24) — a curated law shelf: the diplomas that ground the product,
 *    each with a faithful extract, official links and a last-reviewed date.
 *  - **Validador PDF** — itself split into a second sub-tab level (a second path segment, see
 *    `TechnicalValidatorSection`): PDF/PAdES validation, ASiC container inspection, and the
 *    external-validator technical report shelf.
 *  - **Lista de confiança** — the read-only TSL trust catalog/status surface for
 *    checking the parsed scheme, provider and service trust metadata.
 *  - **Assinatura externa** — operational tracking for redacted external-signer invites
 *    and token-held public envelopes.
 *
 * Each tool is a deep-linkable sub-tab: the active one is a path segment (`/tools/pdf`);
 * its absence means the CAE surface, so `/cae` deep links and the CAE search flow open
 * unchanged. The CAE explorer's own `?code=`/`?rev=` params describe how you are looking at the
 * catalogue rather than where you are, so they stay query params and survive a tool switch. The
 * `SECTIONS` list is the single extension point for future tools.
 */
import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useActiveLocale, useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { Icon, PageHeader } from '../../ui';
import { useSectionNav } from '../../app/navPath';
import { CaeExplorer } from '../cae/CaeExplorer';
import { CaeCatalogPanel } from '../cae/CaeCatalogPanel';
import { LegislationPage } from '../legislation/LegislationPage';
import { TechnicalValidatorSection } from './TechnicalValidatorSection';
import { TrustCatalogPage } from './TrustCatalogPage';
import { ExternalSigningWorkflowsPage } from './ExternalSigningWorkflowsPage';

type ToolsSection = 'cae' | 'legislation' | 'pdf' | 'trust' | 'external-signing';

const SECTIONS: { id: ToolsSection; label: MessageKey; icon: ReactNode }[] = [
  { id: 'cae', label: 'tools.section.cae', icon: <Icon.Layers /> },
  { id: 'legislation', label: 'tools.section.legislacao', icon: <Icon.Scale /> },
  { id: 'pdf', label: 'tools.section.pdfValidator', icon: <Icon.FileText /> },
  { id: 'trust', label: 'tools.section.trust', icon: <Icon.Seal /> },
  { id: 'external-signing', label: 'tools.section.externalSigning', icon: <Icon.PenNib /> },
];

const isToolsSection = (value: string | undefined): value is ToolsSection =>
  SECTIONS.some((s) => s.id === value);

export function ToolsPage() {
  const t = useT();
  const locale = useActiveLocale();
  // The CAE surface is the default, so it carries no segment (keeps `/cae` and the smoke
  // flow landing straight on the explorer). Derived from the path on every render, so a
  // `/tools/pdf` deep link paints the validator on the first frame.
  const { section, select: selectSection } = useSectionNav<ToolsSection>({
    base: '/tools',
    parse: (raw) => (isToolsSection(raw) ? raw : 'cae'),
    fallback: 'cae',
    replace: true,
  });

  // A gilt indicator that glides to the active sub-tab (consistent with the top bar's
  // active-tab indicator). Measured from the active button so it works with the two
  // labels' differing widths and re-measures on locale change / resize; the CSS
  // transition does the sliding and collapses under prefers-reduced-motion.
  const navRef = useRef<HTMLDivElement>(null);
  const btnRefs = useRef<Record<ToolsSection, HTMLButtonElement | null>>({
    cae: null,
    legislation: null,
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

  return (
    <div className="stack">
      {/* No `crumbs`: Tools is a top-level tab with no parent, so a breadcrumb
          would only repeat the title on the line above it. */}
      <PageHeader title={t('tools.title')}>
        <div className="tools-subnav" role="group" aria-label={t('tools.subnav.aria')} ref={navRef}>
          <span
            className="tools-subnav__indicator"
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
              className={s.id === section ? 'tools-subnav__btn is-active' : 'tools-subnav__btn'}
              aria-pressed={s.id === section}
              onClick={() => selectSection(s.id)}
            >
              <span className="tools-subnav__icon" aria-hidden="true">
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
          <TechnicalValidatorSection />
        ) : section === 'external-signing' ? (
          <ExternalSigningWorkflowsPage />
        ) : section === 'legislation' ? (
          <LegislationPage />
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
