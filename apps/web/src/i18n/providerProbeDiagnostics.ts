/**
 * Client-side code → catalog-key map for **provider-credential probe diagnostics** (t112).
 *
 * # The problem this closes
 *
 * The probe's per-check `detail` is an English sentence written by `chancela-api`, and the settings
 * screen rendered it verbatim. An operator on a Portuguese install therefore read a half-translated
 * panel — the client's pt-PT disclaimer directly beneath a paragraph of the server's English. No CI
 * gate could have caught it: `noLiteralUiCopy` and `catalogLeakGate` inspect the web app, and are
 * blind by construction to a sentence that arrives over the wire.
 *
 * # The shape, and why it is this shape
 *
 * The same one `dpiaTemplateLabels.ts` uses, for the same reason: **the wire stays English and
 * stable, and the client maps a stable identifier to a catalog key.** The server now sends
 * `detail_code` alongside — never instead of — `detail`, so the English sentence is still on the
 * wire and still in the audit log.
 *
 * Two completeness guards, in the order they fire:
 *
 * 1. every mapped value is a real `MessageKey` literal, so `tsc` rejects a typo or a key the
 *    catalog is missing;
 * 2. `providerProbeDiagnostics.test.ts` reads `provider_probe_codes.rs` and proves every code the
 *    Rust side can emit is mapped here — so a backend-added code fails loudly rather than silently
 *    rendering English again.
 *
 * Unlike the DPIA maps, **nothing here is positional.** Every code is an explicit identifier; a
 * reordering on the backend cannot desynchronise this file.
 *
 * # What is NOT translated, and must never be
 *
 * `detail_params` values. Every one is a machine identifier or a number: an admin-panel field name
 * (`ama_cert_pem`, `http_basic_username`), a settings path (`signing.tsl_trust_anchor_certs`), a
 * wire enum value (`prod` / `preprod`), a pinned endpoint URL, a count. They are what the operator
 * types into a form or greps a config for, so they reach every locale verbatim — the same rule the
 * DPIA `no_claims` flag identifiers and the server env-var names already follow. The sentence
 * around them is translated; the identifier inside them is not.
 *
 * The `detail` param of `tsl_selection_invalid` / `tsl_anchors_invalid` /
 * `cmd_credential_fields_incomplete` is the one that is prose rather than an identifier: it is the
 * signing path's own message. It stays verbatim too — paraphrasing what a trust-policy builder
 * refused would be inventing a diagnosis — and the translated sentence around it says whose words
 * they are.
 */
import type { ProviderCredentialProbeCheck } from '../api/types';
import type { MessageKey, TParams } from './types';

/** The catalog-key prefix every diagnostic sentence lives under. */
const PREFIX = 'settings.providerCredentials.probe.detail.';

/**
 * Every detail code the probe can emit, mapped to its translated sentence.
 *
 * Grouped exactly as `provider_probe_codes.rs` groups them, so the two files can be read side by
 * side. Adding a code to that file without adding it here fails `providerProbeDiagnostics.test.ts`.
 */
export const PROBE_DETAIL_KEYS: Record<string, MessageKey> = {
  // --- Shared across every mode ---
  entry_disabled: `${PREFIX}entry_disabled`,
  entry_enabled: `${PREFIX}entry_enabled`,
  mode_not_signing_provider: `${PREFIX}mode_not_signing_provider`,
  outbound_client_unavailable: `${PREFIX}outbound_client_unavailable`,

  // --- Chave Móvel Digital preflight ---
  cmd_environment_resolved: `${PREFIX}cmd_environment_resolved`,
  cmd_environment_from_entry: `${PREFIX}cmd_environment_from_entry`,
  cmd_environment_selector_invalid: `${PREFIX}cmd_environment_selector_invalid`,
  cmd_credential_fields_incomplete: `${PREFIX}cmd_credential_fields_incomplete`,
  cmd_credential_assembly_failed: `${PREFIX}cmd_credential_assembly_failed`,
  cmd_credential_fields_present: `${PREFIX}cmd_credential_fields_present`,
  cmd_ama_certificate_parsed: `${PREFIX}cmd_ama_certificate_parsed`,
  cmd_ama_certificate_absent_preprod: `${PREFIX}cmd_ama_certificate_absent_preprod`,
  cmd_ama_certificate_required_prod: `${PREFIX}cmd_ama_certificate_required_prod`,
  cmd_http_basic_configured: `${PREFIX}cmd_http_basic_configured`,
  cmd_http_basic_absent_preprod: `${PREFIX}cmd_http_basic_absent_preprod`,
  cmd_http_basic_required_prod: `${PREFIX}cmd_http_basic_required_prod`,
  cmd_http_transport_ready: `${PREFIX}cmd_http_transport_ready`,
  cmd_http_transport_not_ready: `${PREFIX}cmd_http_transport_not_ready`,
  cmd_endpoint_not_pinned: `${PREFIX}cmd_endpoint_not_pinned`,
  cmd_endpoint_not_https: `${PREFIX}cmd_endpoint_not_https`,
  cmd_endpoint_pinned: `${PREFIX}cmd_endpoint_pinned`,
  cmd_endpoint_reachable: `${PREFIX}cmd_endpoint_reachable`,
  cmd_endpoint_unreachable: `${PREFIX}cmd_endpoint_unreachable`,
  cmd_reachability_skipped_preprod: `${PREFIX}cmd_reachability_skipped_preprod`,
  cmd_live_operation_skipped: `${PREFIX}cmd_live_operation_skipped`,

  // --- Trusted-List trust anchors ---
  tsl_no_list_selected: `${PREFIX}tsl_no_list_selected`,
  tsl_selection_invalid: `${PREFIX}tsl_selection_invalid`,
  tsl_anchors_invalid: `${PREFIX}tsl_anchors_invalid`,
  tsl_unanchored: `${PREFIX}tsl_unanchored`,
  tsl_anchored_from_settings: `${PREFIX}tsl_anchored_from_settings`,
  tsl_anchored_from_environment: `${PREFIX}tsl_anchored_from_environment`,
  tsl_anchored_mixed: `${PREFIX}tsl_anchored_mixed`,

  // --- CSC ---
  csc_base_url_missing: `${PREFIX}csc_base_url_missing`,
  csc_base_url_unsafe: `${PREFIX}csc_base_url_unsafe`,
  csc_base_url_not_https: `${PREFIX}csc_base_url_not_https`,
  csc_base_url_ok: `${PREFIX}csc_base_url_ok`,
  csc_authorization_selector_invalid: `${PREFIX}csc_authorization_selector_invalid`,
  csc_service_authorization_incomplete: `${PREFIX}csc_service_authorization_incomplete`,
  csc_user_authorization_incomplete: `${PREFIX}csc_user_authorization_incomplete`,
  csc_authorization_configured: `${PREFIX}csc_authorization_configured`,
  csc_provider_configuration_invalid: `${PREFIX}csc_provider_configuration_invalid`,
  csc_authenticated: `${PREFIX}csc_authenticated`,
  csc_credentials_listed: `${PREFIX}csc_credentials_listed`,
  csc_configured_credential_not_listed: `${PREFIX}csc_configured_credential_not_listed`,
  csc_credential_selection_required: `${PREFIX}csc_credential_selection_required`,
  csc_credential_selected: `${PREFIX}csc_credential_selected`,
  csc_credential_info_ok: `${PREFIX}csc_credential_info_ok`,
  csc_transport_failed: `${PREFIX}csc_transport_failed`,
  csc_response_too_large: `${PREFIX}csc_response_too_large`,
  csc_http_status_unsuccessful: `${PREFIX}csc_http_status_unsuccessful`,
  csc_service_rejected: `${PREFIX}csc_service_rejected`,
  csc_response_parse_failed: `${PREFIX}csc_response_parse_failed`,
  csc_config_invalid: `${PREFIX}csc_config_invalid`,
  csc_no_signing_credential: `${PREFIX}csc_no_signing_credential`,
  csc_no_signature_returned: `${PREFIX}csc_no_signature_returned`,
  csc_certificate_unparseable: `${PREFIX}csc_certificate_unparseable`,
  csc_malformed_base64: `${PREFIX}csc_malformed_base64`,
  csc_probe_failed: `${PREFIX}csc_probe_failed`,

  // --- SCAP ---
  scap_credentials_incomplete: `${PREFIX}scap_credentials_incomplete`,
  scap_credentials_configured: `${PREFIX}scap_credentials_configured`,
  scap_environment_selector_invalid: `${PREFIX}scap_environment_selector_invalid`,
  scap_base_url_unsafe: `${PREFIX}scap_base_url_unsafe`,
  scap_base_url_not_https: `${PREFIX}scap_base_url_not_https`,
  scap_base_url_ok: `${PREFIX}scap_base_url_ok`,
  scap_provider_configuration_invalid: `${PREFIX}scap_provider_configuration_invalid`,
  scap_providers_listed: `${PREFIX}scap_providers_listed`,
  scap_provider_list_failed: `${PREFIX}scap_provider_list_failed`,

  // --- Local PKCS#12 ---
  pkcs12_material_incomplete: `${PREFIX}pkcs12_material_incomplete`,
  pkcs12_identity_undecryptable: `${PREFIX}pkcs12_identity_undecryptable`,
  pkcs12_identity_loaded: `${PREFIX}pkcs12_identity_loaded`,
  pkcs12_challenge_sign_failed: `${PREFIX}pkcs12_challenge_sign_failed`,
  pkcs12_challenge_signed: `${PREFIX}pkcs12_challenge_signed`,
  pkcs12_challenge_verified: `${PREFIX}pkcs12_challenge_verified`,
  pkcs12_challenge_not_verified: `${PREFIX}pkcs12_challenge_not_verified`,

  // --- AMA field-encryption certificate inspection ---
  // Deliberately narrow. There is no code here meaning "valid" or "trusted", because the server
  // builds no certification path and consults no trust anchor; `ama_cert_trust_not_established`
  // is emitted on every successful parse and says exactly that.
  ama_cert_parsed: `${PREFIX}ama_cert_parsed`,
  ama_cert_unparseable: `${PREFIX}ama_cert_unparseable`,
  ama_cert_rsa_key_present: `${PREFIX}ama_cert_rsa_key_present`,
  ama_cert_rsa_key_absent: `${PREFIX}ama_cert_rsa_key_absent`,
  ama_cert_within_validity: `${PREFIX}ama_cert_within_validity`,
  ama_cert_expired: `${PREFIX}ama_cert_expired`,
  ama_cert_not_yet_valid: `${PREFIX}ama_cert_not_yet_valid`,
  ama_cert_validity_unreadable: `${PREFIX}ama_cert_validity_unreadable`,
  ama_cert_trust_not_established: `${PREFIX}ama_cert_trust_not_established`,
};

/**
 * The catalog key for a detail code, or `undefined` for a code this build does not know.
 *
 * `undefined` is a real outcome, not a defect to be papered over: a server newer than this bundle
 * can emit a code that did not exist when these translations were written. See
 * {@link resolveProbeDetail} for what the caller must then do.
 */
export function probeDetailKey(code: string | undefined): MessageKey | undefined {
  return code ? PROBE_DETAIL_KEYS[code] : undefined;
}

/** What to render for one check's sentence, and whether it is the operator's language. */
export interface ResolvedProbeDetail {
  /** The sentence to show. */
  text: string;
  /**
   * `true` when `text` is the server's raw English because the code was unknown or absent. The
   * caller MUST surface this — a fallback that looks identical to a translation would pass English
   * off as localized copy, and would make the next backend-added code invisible instead of loud.
   */
  untranslated: boolean;
}

/**
 * Resolve one check's sentence into the operator's language.
 *
 * Never blank, never a crash, and never a silent lie: an unknown or absent `detail_code` yields the
 * server's own English with `untranslated: true`, so the UI can mark it as such (and tag it
 * `lang="en"`, which is also what makes a screen reader pronounce it correctly).
 */
export function resolveProbeDetail(
  check: Pick<ProviderCredentialProbeCheck, 'detail' | 'detail_code' | 'detail_params'>,
  t: (key: MessageKey, params?: TParams) => string,
): ResolvedProbeDetail {
  const key = probeDetailKey(check.detail_code);
  if (!key) return { text: check.detail, untranslated: true };
  return { text: t(key, check.detail_params), untranslated: false };
}
