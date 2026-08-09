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
import { type ReactNode } from 'react';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { type SearchCopyKey, useSearchT } from '../../i18n/searchFallback';
import { type CertidaoLookupCopyKey, useCertidaoLookupT } from '../../i18n/certidaoLookupFallback';
import { Icon, PageHeader, SubNav } from '../../ui';
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
  'search' | 'cae' | 'certidao' | 'legislation' | 'pdf' | 'trust' | 'external-signing';

// Three label sources, because two of these tools own their copy in a self-contained fallback
// module rather than the locked 14-locale catalogs. Exactly one is set per section.
type ToolsSectionDefinition =
  | {
      id: ToolsSection;
      label: MessageKey;
      searchLabel?: never;
      certidaoLabel?: never;
      icon: ReactNode;
    }
  | {
      id: ToolsSection;
      label?: never;
      searchLabel: SearchCopyKey;
      certidaoLabel?: never;
      icon: ReactNode;
    }
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
  const { canAny } = usePermissions();
  const canSearch = canAny('search.read');
  // `POST /v1/registry/lookup` enforces `entity.registry.lookup@Global` (t95). The tab is gated on
  // the SAME verb the server enforces — deliberately not on `entity.read`, which used to gate this
  // endpoint and let any Guest fire live outbound requests at the registry service.
  const canLookupCertidao = canAny('entity.registry.lookup');
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

  return (
    <div className="stack">
      {/* No `crumbs`: Tools is a top-level tab with no parent, so a breadcrumb
          would only repeat the title on the line above it. */}
      <PageHeader title={t('tools.title')}>
        {/* The SHARED `<SubNav>`, not a fork. Ferramentas hand-rolled this pill first and the
            generic primitive was aliased onto its styling afterwards; the fork then stopped
            tracking the primitive, and the tool strip — the longest one in the app, seven tools —
            was the one strip in the product with no overflow scroller, so on a narrow shell the
            later tools simply had nowhere to go. Same markup, same gilt indicator, same icons,
            plus the scroller, edge fades and arrows every other section already had. */}
        <SubNav<ToolsSection>
          items={visibleSections.map((s) => ({
            id: s.id,
            label: s.searchLabel
              ? st(s.searchLabel)
              : s.certidaoLabel
                ? ct(s.certidaoLabel)
                : t(s.label),
            icon: s.icon,
          }))}
          active={section}
          onSelect={selectSection}
          ariaLabel={t('tools.subnav.aria')}
        />
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
