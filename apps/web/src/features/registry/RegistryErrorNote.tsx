/**
 * Renders a registry (certidão permanente) failure distinctly by kind. The API maps
 * `RegistryError` onto two statuses the UI must tell apart (plan t11 §2.7):
 *
 *  - `422` — the código de acesso is malformed, or the certidão is missing the data a
 *    given operation needs (a valid NIPC / a mappable forma jurídica). The API's own
 *    message explains exactly what was lacking, so it is shown verbatim.
 *  - `502` — the registry itself could not be reached or returned something that was
 *    not a recognisable certidão (an upstream problem, not the operator's input).
 *
 * Any other error falls back to the generic note.
 */
import { ApiError } from '../../api/client';
import { InlineWarning, ErrorNote } from '../../ui';
import { useT } from '../../i18n';

export function RegistryErrorNote({ error }: { error: unknown }) {
  const t = useT();
  if (error instanceof ApiError && error.status === 422) {
    return (
      <InlineWarning tone="warn" title={t('registry.error.cannotImport')}>
        {error.message}
      </InlineWarning>
    );
  }
  if (error instanceof ApiError && error.status === 502) {
    return (
      <InlineWarning tone="error" title={t('registry.error.unavailableTitle')}>
        <p>{error.message}</p>
        <p className="muted">{t('registry.error.unavailableHint')}</p>
      </InlineWarning>
    );
  }
  return <ErrorNote error={error} />;
}
