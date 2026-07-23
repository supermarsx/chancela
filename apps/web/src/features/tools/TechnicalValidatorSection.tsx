/**
 * The second navigation level inside Tools → Validador PDF.
 *
 * The tool used to stack all three panels on one page — PDF validation, ASiC inspection
 * and the external-validator report shelf — which made a long scroll out of three
 * unrelated jobs. They are now sub-tabs:
 *
 *  - **Assinaturas PDF** (default) — `POST /v1/signature/pdf/validate`
 *  - **Contentores ASiC** — `POST /v1/signature/asic/inspect`
 *  - **Relatórios técnicos** — `GET/POST /v1/external-validator-reports`
 *
 * All three are backed by real endpoints (`crates/chancela-api/src/pdf_signature_validation.rs`,
 * `asic_signature_validation.rs`, `external_validator_evidence.rs`); nothing here is a
 * placeholder for an unbuilt capability.
 *
 * Navigation reuses the shared `<SubNav>` primitive and the path-segment deep-link convention
 * that Configurações and the book detail tabs already use, including the "default section
 * carries no segment" rule — so `/tools/pdf` still lands on PDF validation
 * and existing deep links are unchanged.
 *
 * **Deliberate divergence: this level pushes history instead of replacing it.**
 * `SettingsPage` and the outer Tools tool switch both pass `{ replace: true }`, which
 * means browser Back skips straight out of the surface. That is the failure `t34-lawback`
 * is fixing in Legislação, so the sub-tab switch here pushes: Back returns to the sub-tab
 * you came from and keeps you inside the tool.
 */
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { Icon, SubNav } from '../../ui';
import { useSectionNav } from '../../app/navPath';
import { PdfSignatureValidatorPanel } from './PdfSignatureValidatorPanel';
import { AsicSignatureInspectorPanel } from './AsicSignatureInspectorPanel';
import { ExternalValidatorReportsPanel } from './ExternalValidatorReportsPanel';

export type TechnicalValidatorSectionId = 'pdf' | 'asic' | 'reports';

const DEFAULT_SECTION: TechnicalValidatorSectionId = 'pdf';

const SECTIONS: {
  id: TechnicalValidatorSectionId;
  label: MessageKey;
  icon: React.ReactNode;
}[] = [
  { id: 'pdf', label: 'tools.pdf.section.pdf', icon: <Icon.FileText /> },
  { id: 'asic', label: 'tools.pdf.section.asic', icon: <Icon.Archive /> },
  { id: 'reports', label: 'tools.pdf.section.reports', icon: <Icon.Tray /> },
];

/** An unknown segment falls back to the default rather than rendering nothing. */
export function parseTechnicalValidatorSection(
  value: string | null | undefined,
): TechnicalValidatorSectionId {
  if (value === 'asic' || value === 'reports') return value;
  return DEFAULT_SECTION;
}

export function TechnicalValidatorSection() {
  const t = useT();
  // Second level under `/tools/pdf`. The PDF validator itself is the default, so it
  // carries no segment of its own — `/tools/pdf` stays the canonical link to it.
  const { section, select: selectSection } = useSectionNav<TechnicalValidatorSectionId>({
    base: '/tools/pdf',
    parse: parseTechnicalValidatorSection,
    fallback: DEFAULT_SECTION,
  });

  return (
    <div className="stack">
      <SubNav
        items={SECTIONS.map((s) => ({ id: s.id, label: t(s.label), icon: s.icon }))}
        active={section}
        onSelect={selectSection}
        ariaLabel={t('tools.pdf.subnav.aria')}
      />

      {/* Replays the enter animation on sub-tab switch, keyed on the sub-section so the
          panels' own state changes (a selected file, a returned report) do not re-key. */}
      <div className="route-transition" key={section} data-subanim-key={section}>
        {section === 'asic' ? (
          <AsicSignatureInspectorPanel />
        ) : section === 'reports' ? (
          <ExternalValidatorReportsPanel />
        ) : (
          <PdfSignatureValidatorPanel />
        )}
      </div>
    </div>
  );
}
