/**
 * Field-help copy for the entity forms.
 *
 * Each entry resolves its sentence through i18n at access time (via the module-level,
 * non-React `t` escape hatch — the same one `api/labels.ts` uses), so the tooltips follow
 * the active locale live instead of being frozen Portuguese. Consumers keep reading
 * `entityFieldHelp.<name>` and receive an already-translated string. The source strings
 * live in `fieldHelp.entities.*` (see pt-PT).
 */
import { t } from '../../i18n';

export const entityFieldHelp = {
  get nipc() {
    return t('fieldHelp.entities.nipc');
  },
  get seat() {
    return t('fieldHelp.entities.seat');
  },
  get legalForm() {
    return t('fieldHelp.entities.legalForm');
  },
  get fiscalYearEnd() {
    return t('fieldHelp.entities.fiscalYearEnd');
  },
  get statuteQuorum() {
    return t('fieldHelp.entities.statuteQuorum');
  },
  get statuteMajority() {
    return t('fieldHelp.entities.statuteMajority');
  },
  get statuteNotice() {
    return t('fieldHelp.entities.statuteNotice');
  },
};
