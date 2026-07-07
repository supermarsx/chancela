/**
 * Render an extract's role-tagged, catalog-enriched CAE codes (plan t14 §2.7). Each
 * código shows:
 *
 *  - the code (mono);
 *  - a Principal / Secundário badge — Principal takes the gold accent, Secundário the
 *    neutral tone, so the primary activity reads first;
 *  - the official designation when catalogued, or an honest "não catalogado" note when
 *    the code is unknown (a certidão can carry a withdrawn or mistyped code);
 *  - the level + revision set subtly beneath (e.g. "Subclasse · Rev.4").
 *
 * Used by every surface that renders a `RegistryExtractView` — the provenance page and
 * the import report.
 */
import { Badge } from '../../ui';
import { caeLevelLabels, caeRevisionLabels, caeRoleLabels } from '../../api/labels';
import { useT } from '../../i18n';
import type { CaeRefView } from '../../api/types';

function CaeRef({ cae }: { cae: CaeRefView }) {
  const t = useT();
  const isPrincipal = cae.role === 'Principal';
  const meta =
    cae.level && cae.revision
      ? `${caeLevelLabels[cae.level]} · ${caeRevisionLabels[cae.revision]}`
      : null;

  return (
    <li className="cae-ref">
      <div className="cae-ref__head">
        <code className="mono cae-ref__code">{cae.code}</code>
        <Badge tone={isPrincipal ? 'accent' : 'neutral'}>{caeRoleLabels[cae.role]}</Badge>
        {meta ? <span className="cae-ref__meta muted">{meta}</span> : null}
      </div>
      {cae.designation ? (
        <p className="cae-ref__designation">{cae.designation}</p>
      ) : (
        <p className="cae-ref__designation cae-ref__designation--missing muted">
          {t('cae.ref.notCatalogued')}
        </p>
      )}
    </li>
  );
}

export function CaeRefList({ refs }: { refs: CaeRefView[] }) {
  if (refs.length === 0) return null;
  return (
    <ul className="cae-refs">
      {refs.map((cae) => (
        <CaeRef key={`${cae.code}-${cae.role}`} cae={cae} />
      ))}
    </ul>
  );
}
