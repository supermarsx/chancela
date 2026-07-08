/**
 * Server-driven degraded banner (t54-E4, deliverable #1).
 *
 * Distinct from {@link SafeModeBanner}: safe mode is a CLIENT-boot self-heal (a crashing
 * appearance config), warn-toned. THIS banner is a SERVER signal — the instance found a
 * broken integrity chain on load and put itself in read-only mode (mutations answer 503).
 * It polls `/health` for the frozen `{ integrity, degraded }` signal (t54-E3) and shows a
 * loud, error-toned, always-legible read-only bar the moment the server reports it, and
 * clears it the moment a repair (restore / re-anchor) brings the chain back — no reload
 * needed. It links straight to the "Livros & Integridade" sub-tab where the operator sees
 * the exact break and can repair it.
 */
import { Link } from 'react-router-dom';
import { useDegradedHealth } from '../api/hooks';
import { useT } from '../i18n';

export function DegradedBanner() {
  const t = useT();
  const health = useDegradedHealth();
  const degraded = health.data?.degraded === true || health.data?.integrity === 'broken';
  if (!degraded) return null;

  return (
    <div className="degraded-banner" role="alert" aria-live="assertive">
      <div className="degraded-banner__text">
        <strong className="degraded-banner__title">{t('degraded.title')}</strong>
        <span className="degraded-banner__detail">{t('degraded.detail')}</span>
      </div>
      <Link className="degraded-banner__link" to="/configuracoes?sec=integridade">
        {t('degraded.link')}
      </Link>
    </div>
  );
}
