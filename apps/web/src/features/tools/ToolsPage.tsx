/**
 * Tools (t22-web item 3) — the tools surface reached from the fixed tab bar.
 *
 * A sub-navigation (segmented control) switches between consultation surfaces:
 *  - **Pesquisa** (default, when authorised) — permission-filtered, cross-domain full search.
 *  - **Certidão de Registo Permanente** (t95) — a lookup-only consultation: enter a código de
 *    acesso, read what the registry returns, keep nothing. Separate from the entity import flow on
 *    purpose, and it persists nothing at all (see `CertidaoLookupPage`).
 *  - **Catálogo CAE** — the CAE explorer (search + revision switch + hierarchy drill-down)
 *    and the catalog's state + "Atualizar catálogo" refresh, relocated here from the former
 *    standalone /cae page, which now redirects to `/tools/cae`.
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
 * its absence means Search. The CAE explorer's own `?code=`/`?rev=` params describe how you are
 * looking at the
 * catalogue rather than where you are, so they stay query params and survive a tool switch. The
 * `SECTIONS` list is the single extension point for future tools.
 */
import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useActiveLocale, useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { type SearchCopyKey, useSearchT } from '../../i18n/searchFallback';
import {
  type CertidaoLookupCopyKey,
  useCertidaoLookupT,
} from '../../i18n/certidaoLookupFallback';
import { Icon, PageHeader } from '../../ui';
import { useSectionNav } from '../../app/navPath';
import { CaeExplorer } from '../cae/CaeExplorer';
import { CaeCatalogPanel } from '../cae/CaeCatalogPanel';
import { LegislationPage } from '../legislation/LegislationPage';
import { TechnicalValidatorSection } from './TechnicalValidatorSection';
import { TrustCatalogPage } from './TrustCatalogPage';
import { ExternalSigningWorkflowsPage } from './ExternalSigningWorkflowsPage';
import { CertidaoLookupPage } from './CertidaoLookupPage';
import { SearchPage } from './SearchPage';
import { usePermissions } from '../session/permissions';

type ToolsSection =
  | 'search'
  | 'cae'
  | 'certidao'
  | 'legislation'
  | 'pdf'
  | 'trust'
  | 'external-signing';

// Three label sources, because two of these tools own their copy in a self-contained fallback
// module rather than the locked 14-locale catalogs. Exactly one is set per section.
type ToolsSectionDefinition =
  | { id: ToolsSection; label: MessageKey; searchLabel?: never; certidaoLabel?: never; icon: ReactNode }
  | { id: ToolsSection; label?: never; searchLabel: SearchCopyKey; certidaoLabel?: never; icon: ReactNode }
  | {
      id: ToolsSection;
      label?: never;
      searchLabel?: never;
      certidaoLabel: CertidaoLookupCopyKey;
      icon: ReactNode;
    };

const SECTIONS: ToolsSectionDefinition[] = [
  { id: 'search', searchLabel: 'tools.section.search', icon: <Icon.Search /> },
  { id: 'cae', label: 'tools.section.cae', icon: <Icon.Layers /> },
  // A lookup-only Certidão de Registo Permanente consultation. Deliberately its own tool rather
  // than a mode of the import flow: it persists nothing (see `CertidaoLookupPage`).
  { id: 'certidao', certidaoLabel: 'tools.section.certidao', icon: <Icon.IdCard /> },
  { id: 'legislation', label: 'tools.section.legislacao', icon: <Icon.Scale /> },
  { id: 'pdf', label: 'tools.section.pdfValidator', icon: <Icon.FileText /> },
  { id: 'trust', label: 'tools.section.trust', icon: <Icon.Seal /> },
  { id: 'external-signing', label: 'tools.section.externalSigning', icon: <Icon.PenNib /> },
];

const isToolsSection = (value: string | undefined): value is ToolsSection =>
  SECTIONS.some((s) => s.id === value);

export function ToolsPage() {
  const t = useT();
  const st = useSearchT();
  const ct = useCertidaoLookupT();
  const locale = useActiveLocale();
  const { canAny } = usePermissions();
  const canSearch = canAny('search.read');
  // `POST /v1/registry/lookup` enforces `entity.read@Global`. The tab is gated on the SAME verb the
  // server enforces — deliberately not on a lookup-specific one, which would be a phantom verb
  // enforced only in the client (the cost of which `book.reopen` already demonstrated).
  const canLookupCertidao = canAny('entity.read');
  const visibleSections = SECTIONS.filter(
    (candidate) =>
      (candidate.id !== 'search' || canSearch) &&
      (candidate.id !== 'certidao' || canLookupCertidao),
  );
  // Search is the default and carries no segment. A principal without search.read falls back to
  // CAE without ever rendering the Search label or component; CAE still has the canonical
  // `/tools/cae` address when selected or reached through the legacy `/cae` redirect.
  const { section, select: selectSection } = useSectionNav<ToolsSection>({
    base: '/tools',
    parse: (raw) => {
      if (raw === undefined) return canSearch ? 'search' : 'cae';
      if (
        isToolsSection(raw) &&
        (raw !== 'search' || canSearch) &&
        (raw !== 'certidao' || canLookupCertidao)
      ) {
        return raw;
      }
      return canSearch ? 'search' : 'cae';
    },
    fallback: 'search',
    replace: true,
  });

  // A gilt indicator that glides to the active sub-tab (consistent with the top bar's
  // active-tab indicator). Measured from the active button so it works with the two
  // labels' differing widths and re-measures on locale change / resize; the CSS
  // transition does the sliding and collapses under prefers-reduced-motion.
  const navRef = useRef<HTMLDivElement>(null);
  const btnRefs = useRef<Record<ToolsSection, HTMLButtonElement | null>>({
    search: null,
    cae: null,
    certidao: null,
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
          {visibleSections.map((s) => (
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
              {s.searchLabel
                ? st(s.searchLabel)
                : s.certidaoLabel
                  ? ct(s.certidaoLabel)
                  : t(s.label)}
            </button>
          ))}
        </div>
      </PageHeader>

      {/* The content region replays the route-enter animation when the sub-tab changes.
          Keying on `section` (the `tool` param) means switching tool re-animates, while
          the CAE explorer's own `?code=`/`?rev=` and Legislação's `?q=` param changes do
          NOT re-key (no distracting replay). Reduced-motion collapses the animation. */}
      <div className="route-transition" key={section} data-anim-key={section}>
        {section === 'search' ? (
          <SearchPage />
        ) : section === 'certidao' ? (
          <CertidaoLookupPage />
        ) : section === 'trust' ? (
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
