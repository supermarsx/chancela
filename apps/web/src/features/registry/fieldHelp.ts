/**
 * Field-help copy for the registry (certidão) import & provenance surfaces.
 *
 * Each entry resolves its sentence through i18n at access time (via the module-level,
 * non-React `t` escape hatch — the same one `api/labels.ts` uses), so the tooltips follow
 * the active locale live instead of being frozen Portuguese. Consumers keep reading
 * `registryFieldHelp.<name>` and receive an already-translated string. The source strings
 * live in `fieldHelp.registry.*` (see pt-PT).
 */
import { t } from '../../i18n';

export const registryFieldHelp = {
  get accessCode() {
    return t('fieldHelp.registry.accessCode');
  },
  get email() {
    return t('fieldHelp.registry.email');
  },
  get firma() {
    return t('fieldHelp.registry.firma');
  },
  get nipc() {
    return t('fieldHelp.registry.nipc');
  },
  get legalForm() {
    return t('fieldHelp.registry.legalForm');
  },
  get matricula() {
    return t('fieldHelp.registry.matricula');
  },
  get sede() {
    return t('fieldHelp.registry.sede');
  },
  get dataConstituicao() {
    return t('fieldHelp.registry.dataConstituicao');
  },
  get capital() {
    return t('fieldHelp.registry.capital');
  },
  get objeto() {
    return t('fieldHelp.registry.objeto');
  },
  get cae() {
    return t('fieldHelp.registry.cae');
  },
  get accessCodeMasked() {
    return t('fieldHelp.registry.accessCodeMasked');
  },
  get retrievedAt() {
    return t('fieldHelp.registry.retrievedAt');
  },
  get conservatoria() {
    return t('fieldHelp.registry.conservatoria');
  },
  get oficial() {
    return t('fieldHelp.registry.oficial');
  },
  get subscribedOn() {
    return t('fieldHelp.registry.subscribedOn');
  },
  get validUntil() {
    return t('fieldHelp.registry.validUntil');
  },
  get source() {
    return t('fieldHelp.registry.source');
  },
  get digest() {
    return t('fieldHelp.registry.digest');
  },
  get naturezaJuridica() {
    return t('fieldHelp.registry.naturezaJuridica');
  },
  get fiscalYearEnd() {
    return t('fieldHelp.registry.fiscalYearEnd');
  },
  get capitalRealization() {
    return t('fieldHelp.registry.capitalRealization');
  },
  get deliberationDate() {
    return t('fieldHelp.registry.deliberationDate');
  },
  get formaObrigar() {
    return t('fieldHelp.registry.formaObrigar');
  },
};
