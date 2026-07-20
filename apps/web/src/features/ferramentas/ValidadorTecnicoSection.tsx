/**
 * The second navigation level inside Ferramentas → Validador PDF.
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
 * Navigation reuses the shared `<SubNav>` primitive and the `?sec=` deep-link convention
 * that Configurações and the book detail tabs already use, including the "default section
 * carries no `sec` param" rule — so `/ferramentas?tool=pdf` still lands on PDF validation
 * and existing deep links are unchanged.
 *
 * **Deliberate divergence: this level pushes history instead of replacing it.**
 * `SettingsPage` and the outer Ferramentas tool switch both pass `{ replace: true }`, which
 * means browser Back skips straight out of the surface. That is the failure `t34-lawback`
 * is fixing in Legislação, so the sub-tab switch here pushes: Back returns to the sub-tab
 * you came from and keeps you inside the tool.
 */
import { useSearchParams } from 'react-router-dom';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { Icon, SubNav } from '../../ui';
import { PdfSignatureValidatorPanel } from './PdfSignatureValidatorPanel';
import { AsicSignatureInspectorPanel } from './AsicSignatureInspectorPanel';
import { ExternalValidatorReportsPanel } from './ExternalValidatorReportsPanel';

export type ValidadorTecnicoSectionId = 'pdf' | 'asic' | 'relatorios';

const DEFAULT_SECTION: ValidadorTecnicoSectionId = 'pdf';

const SECTIONS: {
  id: ValidadorTecnicoSectionId;
  label: MessageKey;
  icon: React.ReactNode;
}[] = [
  { id: 'pdf', label: 'tools.pdf.section.pdf', icon: <Icon.FileText /> },
  { id: 'asic', label: 'tools.pdf.section.asic', icon: <Icon.Archive /> },
  { id: 'relatorios', label: 'tools.pdf.section.reports', icon: <Icon.Tray /> },
];

/** An unknown `sec` falls back to the default rather than rendering nothing. */
export function parseValidadorTecnicoSection(value: string | null): ValidadorTecnicoSectionId {
  if (value === 'asic' || value === 'relatorios') return value;
  return DEFAULT_SECTION;
}

export function ValidadorTecnicoSection() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const section = parseValidadorTecnicoSection(params.get('sec'));

  function selectSection(next: ValidadorTecnicoSectionId) {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      // The PDF validator is the default, so it carries no `sec` param — `?tool=pdf`
      // stays the canonical link to it.
      if (next === DEFAULT_SECTION) p.delete('sec');
      else p.set('sec', next);
      return p;
    });
  }

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
        ) : section === 'relatorios' ? (
          <ExternalValidatorReportsPanel />
        ) : (
          <PdfSignatureValidatorPanel />
        )}
      </div>
    </div>
  );
}
