/**
 * Field-help copy for the signature-provider credential forms (wp18-d).
 *
 * Each entry resolves its sentence through i18n at access time (via the module-level,
 * non-React `t` escape hatch — the same one `registry/fieldHelp.ts` uses), so the tooltips
 * follow the active locale live instead of being frozen Portuguese. Each string pairs a
 * plain description of the field with a concrete, example-style value. Consumers keep
 * reading `providerCredentialsFieldHelp.<name>` and receive an already-translated string.
 *
 * The keys are the raw backend field names (snake_case, matching the `SecretFieldSpec` /
 * `SelectorFieldSpec` `name`s) plus the entry-level pseudo-fields, so the component can look
 * one up dynamically as `providerCredentialsFieldHelp[spec.name]`. The source strings live in
 * `settings.providerCredentials.help.*` (see pt-PT).
 */
import { t } from '../../i18n';

export const providerCredentialsFieldHelp = {
  // Entry-level fields.
  get mode() {
    return t('settings.providerCredentials.help.mode');
  },
  get providerId() {
    return t('settings.providerCredentials.help.providerId');
  },
  get label() {
    return t('settings.providerCredentials.help.label');
  },
  get enabled() {
    return t('settings.providerCredentials.help.enabled');
  },
  get endpoint() {
    return t('settings.providerCredentials.help.endpoint');
  },
  get pfx() {
    return t('settings.providerCredentials.help.pfx');
  },
  // Secret fields (keyed by backend field name).
  get application_id() {
    return t('settings.providerCredentials.help.applicationId');
  },
  get http_basic_username() {
    return t('settings.providerCredentials.help.httpBasicUsername');
  },
  get http_basic_password() {
    return t('settings.providerCredentials.help.httpBasicPassword');
  },
  get ama_cert_pem() {
    return t('settings.providerCredentials.help.amaCertPem');
  },
  get client_id() {
    return t('settings.providerCredentials.help.clientId');
  },
  get client_secret() {
    return t('settings.providerCredentials.help.clientSecret');
  },
  get access_token() {
    return t('settings.providerCredentials.help.accessToken');
  },
  get secret() {
    return t('settings.providerCredentials.help.secret');
  },
  get passphrase() {
    return t('settings.providerCredentials.help.passphrase');
  },
  // Selector fields (keyed by backend field name).
  get env() {
    return t('settings.providerCredentials.help.env');
  },
  get authorization() {
    return t('settings.providerCredentials.help.authorization');
  },
  get credential_id() {
    return t('settings.providerCredentials.help.credentialId');
  },
  get scope() {
    return t('settings.providerCredentials.help.scope');
  },
  get sandbox() {
    return t('settings.providerCredentials.help.sandbox');
  },
  get environment() {
    return t('settings.providerCredentials.help.environment');
  },
  get friendly_name() {
    return t('settings.providerCredentials.help.friendlyName');
  },
  get local_key_id_hex() {
    return t('settings.providerCredentials.help.localKeyId');
  },
} satisfies Record<string, string>;

/** Look up help by a dynamic backend field name (undefined for names without help copy). */
export function providerCredentialFieldHelp(name: string): string | undefined {
  return (providerCredentialsFieldHelp as Record<string, string>)[name];
}
