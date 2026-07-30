//! The stable machine vocabulary for provider-credential **probe diagnostics** (t112).
//!
//! # Why this module exists
//!
//! Every per-check `detail` a probe returns used to be an English sentence and nothing else, and
//! the settings screen rendered it verbatim. An operator running a Portuguese install therefore
//! read a half-translated panel: the client's own disclaimer in pt-PT, and directly above it a
//! paragraph of English prose the server had written. Neither CI gate could see it —
//! `noLiteralUiCopy` and `catalogLeakGate` inspect the web app, and by construction cannot look at
//! a sentence that arrives over the wire.
//!
//! The fix follows the pattern already established by the DPIA guidance template
//! (`apps/web/src/i18n/dpiaTemplateLabels.ts`): **the wire stays English and stable, and the client
//! maps a stable identifier to a catalog key.** So each check now carries a
//! [`ProviderProbeCheck::detail_code`](crate::provider_credentials_write::ProviderProbeCheck) drawn
//! from the constants below, *alongside* — never instead of — the English `detail`. The English
//! sentence is still on the wire, still in the audit log, and is still what a client too old (or
//! too new) to know a code renders.
//!
//! # The rules these constants obey
//!
//! - **English, snake_case, never translated.** They are machine identifiers, exactly like the
//!   `status` vocabulary (`passed` / `failed` / `skipped`) and the response's
//!   `error` vocabulary (`configuration_incomplete`, `interactive_required`, …) that already ride
//!   this DTO. This module *extends* that existing vocabulary rather than duplicating it: the codes
//!   here name the **detail sentence of one check**, which is finer-grained than either the
//!   per-response `error` or the per-check `name` (one `name` — `trusted_list_anchors` — has seven
//!   distinct outcomes, and `endpoint_reachable` has four).
//! - **One code per distinct sentence.** Two checks that say the same thing share a code (the
//!   bounded outbound client, for instance, fails identically for CSC and SCAP). Two checks that
//!   say different things never do, even under the same `name`.
//! - **A code is append-only.** Renaming one silently changes what a client renders; deleting one
//!   makes an older client's translation dead. Add, do not edit.
//! - **Interpolated values are machine identifiers or numbers, never prose.** `{environment}`
//!   is the `prod`/`preprod` wire value, `{endpoint}` a pinned URL constant, `{username_field}` an
//!   admin-panel field name. Those must reach the operator verbatim in every locale. Where the
//!   varying part would have been *prose* — the trust-anchor provenance clause, which reads "all of
//!   them from the environment" / "…from the signing settings" / a mixture — the outcome is split
//!   into separate codes instead, so no translator has to drop an English clause into an inflected
//!   sentence.
//!
//! # The guard
//!
//! [`ALL_PROBE_DETAIL_CODES`] is the closed list, and
//! `apps/web/src/i18n/providerProbeDiagnostics.test.ts` reads **this file** to prove the client maps
//! every one of them to a catalog key. A code added here without a translation fails that test
//! loudly, rather than silently rendering English on the settings screen again.

/// The stored credential entry is switched off, so nothing else was examined.
pub const ENTRY_DISABLED: &str = "entry_disabled";
/// The stored credential entry is switched on.
pub const ENTRY_ENABLED: &str = "entry_enabled";
/// The entry's mode is not a signing provider at all (SMTP / TOTP share the credential store).
pub const MODE_NOT_SIGNING_PROVIDER: &str = "mode_not_signing_provider";
/// The bounded outbound HTTP client could not be constructed, so no request was attempted.
pub const OUTBOUND_CLIENT_UNAVAILABLE: &str = "outbound_client_unavailable";

// --- Chave Móvel Digital preflight ---------------------------------------------------------------

/// The entry declares no environment and inherits the deployment default. Params: `environment`
/// (`prod` / `preprod`).
pub const CMD_ENVIRONMENT_RESOLVED: &str = "cmd_environment_resolved";
/// The entry's own `env` selector decides, and this is what it says (t113). Params: `environment`.
pub const CMD_ENVIRONMENT_FROM_ENTRY: &str = "cmd_environment_from_entry";
/// The entry's `env` selector is neither `prod` nor `preprod`, so the environment is undetermined.
/// Refused rather than defaulted: an uninterpretable selector must not decide a production
/// boundary.
pub const CMD_ENVIRONMENT_SELECTOR_INVALID: &str = "cmd_environment_selector_invalid";
/// The signing path's own assembler refused the entry and named the missing admin-panel fields.
/// Params: `detail` (the assembler's own sanitized message, field names only).
pub const CMD_CREDENTIAL_FIELDS_INCOMPLETE: &str = "cmd_credential_fields_incomplete";
/// The assembler refused for a reason this classifier cannot name specifically.
pub const CMD_CREDENTIAL_ASSEMBLY_FAILED: &str = "cmd_credential_assembly_failed";
/// Every credential field this environment requires is present.
pub const CMD_CREDENTIAL_FIELDS_PRESENT: &str = "cmd_credential_fields_present";
/// The stored AMA field-encryption certificate parsed and the encryptor was built.
pub const CMD_AMA_CERTIFICATE_PARSED: &str = "cmd_ama_certificate_parsed";
/// No AMA certificate is stored, which preprod tolerates.
pub const CMD_AMA_CERTIFICATE_ABSENT_PREPROD: &str = "cmd_ama_certificate_absent_preprod";
/// Production demands the AMA certificate. Params: `field` (the admin-panel field name).
pub const CMD_AMA_CERTIFICATE_REQUIRED_PROD: &str = "cmd_ama_certificate_required_prod";
/// HTTP BasicAuth credentials are stored.
pub const CMD_HTTP_BASIC_CONFIGURED: &str = "cmd_http_basic_configured";
/// No BasicAuth is stored, which preprod may tolerate.
pub const CMD_HTTP_BASIC_ABSENT_PREPROD: &str = "cmd_http_basic_absent_preprod";
/// Production demands BasicAuth. Params: `username_field`, `password_field`.
pub const CMD_HTTP_BASIC_REQUIRED_PROD: &str = "cmd_http_basic_required_prod";
/// The resolved configuration satisfies the real AMA HTTP transport.
pub const CMD_HTTP_TRANSPORT_READY: &str = "cmd_http_transport_ready";
/// The resolved configuration cannot drive the real AMA HTTP transport.
pub const CMD_HTTP_TRANSPORT_NOT_READY: &str = "cmd_http_transport_not_ready";
/// The resolved SCMD endpoint is not this environment's pinned constant, or failed egress policy.
pub const CMD_ENDPOINT_NOT_PINNED: &str = "cmd_endpoint_not_pinned";
/// The SCMD endpoint is not HTTPS, so no stored credential may be sent to it.
pub const CMD_ENDPOINT_NOT_HTTPS: &str = "cmd_endpoint_not_https";
/// The SCMD endpoint is the pinned constant, over HTTPS. Params: `endpoint`.
pub const CMD_ENDPOINT_PINNED: &str = "cmd_endpoint_pinned";
/// A TLS handshake with AMA production succeeded. No SCMD operation was invoked.
pub const CMD_ENDPOINT_REACHABLE: &str = "cmd_endpoint_reachable";
/// AMA production could not be reached. No SCMD operation was invoked.
pub const CMD_ENDPOINT_UNREACHABLE: &str = "cmd_endpoint_unreachable";
/// Reachability is a production-only question and this deployment is preprod.
pub const CMD_REACHABILITY_SKIPPED_PREPROD: &str = "cmd_reachability_skipped_preprod";
/// CMD has no safe non-signing health operation, so none was performed.
pub const CMD_LIVE_OPERATION_SKIPPED: &str = "cmd_live_operation_skipped";

// --- Trusted-List trust anchors -------------------------------------------------------------------

/// No Trusted List is selected, so no qualified signature can be authenticated.
pub const TSL_NO_LIST_SELECTED: &str = "tsl_no_list_selected";
/// The Trusted List *selection* is invalid. Params: `detail`.
pub const TSL_SELECTION_INVALID: &str = "tsl_selection_invalid";
/// A configured anchor could not be parsed, so the trust policy fails closed. Params: `detail`,
/// `certs_setting`, `digest_setting`.
pub const TSL_ANCHORS_INVALID: &str = "tsl_anchors_invalid";
/// A list is selected and the resolved anchor set is empty. Params: `certs_setting`,
/// `digest_setting`.
pub const TSL_UNANCHORED: &str = "tsl_unanchored";
/// Anchors resolved, all from the signing settings. Params: `total`.
pub const TSL_ANCHORED_FROM_SETTINGS: &str = "tsl_anchored_from_settings";
/// Anchors resolved, all from the environment. Params: `total`.
pub const TSL_ANCHORED_FROM_ENVIRONMENT: &str = "tsl_anchored_from_environment";
/// Anchors resolved from both sources. Params: `total`, `from_env`, `from_settings`.
pub const TSL_ANCHORED_MIXED: &str = "tsl_anchored_mixed";

// --- CSC (Cloud Signature Consortium) --------------------------------------------------------------

/// The entry stores no CSC base URL.
pub const CSC_BASE_URL_MISSING: &str = "csc_base_url_missing";
/// The CSC base URL failed the outbound-network safety policy.
pub const CSC_BASE_URL_UNSAFE: &str = "csc_base_url_unsafe";
/// The CSC base URL is not HTTPS.
pub const CSC_BASE_URL_NOT_HTTPS: &str = "csc_base_url_not_https";
/// The CSC base URL passed egress policy and is HTTPS.
pub const CSC_BASE_URL_OK: &str = "csc_base_url_ok";
/// The `authorization` selector is neither `service` nor `user`.
pub const CSC_AUTHORIZATION_SELECTOR_INVALID: &str = "csc_authorization_selector_invalid";
/// Service authorization is selected but its fields are missing. Params: `client_id_field`,
/// `client_secret_field`.
pub const CSC_SERVICE_AUTHORIZATION_INCOMPLETE: &str = "csc_service_authorization_incomplete";
/// User authorization is selected but no access token is stored. Params: `token_field`.
pub const CSC_USER_AUTHORIZATION_INCOMPLETE: &str = "csc_user_authorization_incomplete";
/// The stored fields satisfy the selected authorization model.
pub const CSC_AUTHORIZATION_CONFIGURED: &str = "csc_authorization_configured";
/// The assembled CSC provider configuration is invalid.
pub const CSC_PROVIDER_CONFIGURATION_INVALID: &str = "csc_provider_configuration_invalid";
/// CSC authentication completed, without asking any signer to authorize anything.
pub const CSC_AUTHENTICATED: &str = "csc_authenticated";
/// `credentials/list` answered. Params: `count`.
pub const CSC_CREDENTIALS_LISTED: &str = "csc_credentials_listed";
/// The configured `credential_id` was not among the listed credentials.
pub const CSC_CONFIGURED_CREDENTIAL_NOT_LISTED: &str = "csc_configured_credential_not_listed";
/// More than one credential exists and none is configured. Params: `selector`.
pub const CSC_CREDENTIAL_SELECTION_REQUIRED: &str = "csc_credential_selection_required";
/// Exactly one signing credential was selected.
pub const CSC_CREDENTIAL_SELECTED: &str = "csc_credential_selected";
/// `credentials/info` returned a parseable certificate. Params: `issuer_count`.
pub const CSC_CREDENTIAL_INFO_OK: &str = "csc_credential_info_ok";
/// The CSC endpoint could not be reached inside the bounded request.
pub const CSC_TRANSPORT_FAILED: &str = "csc_transport_failed";
/// The CSC response exceeded the safety limit.
pub const CSC_RESPONSE_TOO_LARGE: &str = "csc_response_too_large";
/// The CSC endpoint answered with an unsuccessful HTTP status.
pub const CSC_HTTP_STATUS_UNSUCCESSFUL: &str = "csc_http_status_unsuccessful";
/// The CSC service rejected the safe probe operation.
pub const CSC_SERVICE_REJECTED: &str = "csc_service_rejected";
/// The CSC response did not match the expected protocol shape.
pub const CSC_RESPONSE_PARSE_FAILED: &str = "csc_response_parse_failed";
/// The CSC probe configuration is incomplete or invalid.
pub const CSC_CONFIG_INVALID: &str = "csc_config_invalid";
/// The CSC account exposes no signing credential at all.
pub const CSC_NO_SIGNING_CREDENTIAL: &str = "csc_no_signing_credential";
/// The CSC service returned no signature.
pub const CSC_NO_SIGNATURE_RETURNED: &str = "csc_no_signature_returned";
/// The CSC credential certificate could not be parsed.
pub const CSC_CERTIFICATE_UNPARSEABLE: &str = "csc_certificate_unparseable";
/// The CSC response contained malformed base64.
pub const CSC_MALFORMED_BASE64: &str = "csc_malformed_base64";
/// The CSC probe failed for a reason this classifier cannot name specifically.
pub const CSC_PROBE_FAILED: &str = "csc_probe_failed";

// --- SCAP (AMA professional attributes) -----------------------------------------------------------

/// The SCAP application credentials are missing. Params: `application_id_field`, `secret_field`.
pub const SCAP_CREDENTIALS_INCOMPLETE: &str = "scap_credentials_incomplete";
/// The SCAP application credentials are stored.
pub const SCAP_CREDENTIALS_CONFIGURED: &str = "scap_credentials_configured";
/// The `environment` selector is neither `prod` nor `preprod`.
pub const SCAP_ENVIRONMENT_SELECTOR_INVALID: &str = "scap_environment_selector_invalid";
/// The SCAP base URL failed the outbound-network safety policy.
pub const SCAP_BASE_URL_UNSAFE: &str = "scap_base_url_unsafe";
/// The SCAP base URL is not HTTPS.
pub const SCAP_BASE_URL_NOT_HTTPS: &str = "scap_base_url_not_https";
/// The SCAP base URL passed egress policy and is HTTPS.
pub const SCAP_BASE_URL_OK: &str = "scap_base_url_ok";
/// The assembled SCAP provider configuration is invalid.
pub const SCAP_PROVIDER_CONFIGURATION_INVALID: &str = "scap_provider_configuration_invalid";
/// The provider listing answered. Params: `count`.
pub const SCAP_PROVIDERS_LISTED: &str = "scap_providers_listed";
/// The provider listing failed or returned an invalid response.
pub const SCAP_PROVIDER_LIST_FAILED: &str = "scap_provider_list_failed";

// --- Local PKCS#12 ---------------------------------------------------------------------------------

/// The stored PKCS#12 material or identity selector is incomplete or malformed.
pub const PKCS12_MATERIAL_INCOMPLETE: &str = "pkcs12_material_incomplete";
/// The stored PKCS#12 identity could not be decrypted and selected.
pub const PKCS12_IDENTITY_UNDECRYPTABLE: &str = "pkcs12_identity_undecryptable";
/// The stored PKCS#12 identity was decrypted and selected.
pub const PKCS12_IDENTITY_LOADED: &str = "pkcs12_identity_loaded";
/// The private key could not sign the non-document probe challenge.
pub const PKCS12_CHALLENGE_SIGN_FAILED: &str = "pkcs12_challenge_sign_failed";
/// The private key signed a random, domain-separated, non-document challenge.
pub const PKCS12_CHALLENGE_SIGNED: &str = "pkcs12_challenge_signed";
/// The challenge signature verified locally against the selected certificate.
pub const PKCS12_CHALLENGE_VERIFIED: &str = "pkcs12_challenge_verified";
/// The challenge signature did NOT verify against the selected certificate.
pub const PKCS12_CHALLENGE_NOT_VERIFIED: &str = "pkcs12_challenge_not_verified";

// --- AMA field-encryption certificate inspection (t112) --------------------------------------------
//
// These describe a CANDIDATE certificate an operator is about to paste into `ama_cert_pem`, and
// they are deliberately narrower than they could be. The inspection builds no chain, consults no
// trust anchor and fetches no Trusted List, so it can say what the certificate *is* and never that
// it is the right one. `AMA_CERT_TRUST_NOT_ESTABLISHED` is emitted on every successful parse and
// says exactly that; there is no code here that means "valid", because nothing here establishes it.

/// The text parses as an X.509 certificate.
pub const AMA_CERT_PARSED: &str = "ama_cert_parsed";
/// The text is not a PEM-encoded X.509 certificate. Params: `detail` (the parser's own message).
pub const AMA_CERT_UNPARSEABLE: &str = "ama_cert_unparseable";
/// The certificate carries an RSA public key — what field encryption needs. Params: `bits`.
pub const AMA_CERT_RSA_KEY_PRESENT: &str = "ama_cert_rsa_key_present";
/// It carries no RSA public key, so no field encryptor can be built from it. Params: `detail`.
pub const AMA_CERT_RSA_KEY_ABSENT: &str = "ama_cert_rsa_key_absent";
/// The current server time falls inside the certificate's validity window.
pub const AMA_CERT_WITHIN_VALIDITY: &str = "ama_cert_within_validity";
/// The validity window has already ended.
pub const AMA_CERT_EXPIRED: &str = "ama_cert_expired";
/// The validity window has not started yet.
pub const AMA_CERT_NOT_YET_VALID: &str = "ama_cert_not_yet_valid";
/// The validity dates could not be read as timestamps, so the window could not be judged.
pub const AMA_CERT_VALIDITY_UNREADABLE: &str = "ama_cert_validity_unreadable";
/// The standing statement of what the inspection did NOT determine.
pub const AMA_CERT_TRUST_NOT_ESTABLISHED: &str = "ama_cert_trust_not_established";

/// Every detail code a probe can emit, in one closed list.
///
/// Read by `provider_probe_codes` unit tests (uniqueness, snake_case) and — as the file's text — by
/// `apps/web/src/i18n/providerProbeDiagnostics.test.ts`, which proves the client has a translated
/// catalog key for each. Keep it sorted the way the constants are declared, grouped by mode.
pub const ALL_PROBE_DETAIL_CODES: &[&str] = &[
    ENTRY_DISABLED,
    ENTRY_ENABLED,
    MODE_NOT_SIGNING_PROVIDER,
    OUTBOUND_CLIENT_UNAVAILABLE,
    CMD_ENVIRONMENT_RESOLVED,
    CMD_ENVIRONMENT_FROM_ENTRY,
    CMD_ENVIRONMENT_SELECTOR_INVALID,
    CMD_CREDENTIAL_FIELDS_INCOMPLETE,
    CMD_CREDENTIAL_ASSEMBLY_FAILED,
    CMD_CREDENTIAL_FIELDS_PRESENT,
    CMD_AMA_CERTIFICATE_PARSED,
    CMD_AMA_CERTIFICATE_ABSENT_PREPROD,
    CMD_AMA_CERTIFICATE_REQUIRED_PROD,
    CMD_HTTP_BASIC_CONFIGURED,
    CMD_HTTP_BASIC_ABSENT_PREPROD,
    CMD_HTTP_BASIC_REQUIRED_PROD,
    CMD_HTTP_TRANSPORT_READY,
    CMD_HTTP_TRANSPORT_NOT_READY,
    CMD_ENDPOINT_NOT_PINNED,
    CMD_ENDPOINT_NOT_HTTPS,
    CMD_ENDPOINT_PINNED,
    CMD_ENDPOINT_REACHABLE,
    CMD_ENDPOINT_UNREACHABLE,
    CMD_REACHABILITY_SKIPPED_PREPROD,
    CMD_LIVE_OPERATION_SKIPPED,
    TSL_NO_LIST_SELECTED,
    TSL_SELECTION_INVALID,
    TSL_ANCHORS_INVALID,
    TSL_UNANCHORED,
    TSL_ANCHORED_FROM_SETTINGS,
    TSL_ANCHORED_FROM_ENVIRONMENT,
    TSL_ANCHORED_MIXED,
    CSC_BASE_URL_MISSING,
    CSC_BASE_URL_UNSAFE,
    CSC_BASE_URL_NOT_HTTPS,
    CSC_BASE_URL_OK,
    CSC_AUTHORIZATION_SELECTOR_INVALID,
    CSC_SERVICE_AUTHORIZATION_INCOMPLETE,
    CSC_USER_AUTHORIZATION_INCOMPLETE,
    CSC_AUTHORIZATION_CONFIGURED,
    CSC_PROVIDER_CONFIGURATION_INVALID,
    CSC_AUTHENTICATED,
    CSC_CREDENTIALS_LISTED,
    CSC_CONFIGURED_CREDENTIAL_NOT_LISTED,
    CSC_CREDENTIAL_SELECTION_REQUIRED,
    CSC_CREDENTIAL_SELECTED,
    CSC_CREDENTIAL_INFO_OK,
    CSC_TRANSPORT_FAILED,
    CSC_RESPONSE_TOO_LARGE,
    CSC_HTTP_STATUS_UNSUCCESSFUL,
    CSC_SERVICE_REJECTED,
    CSC_RESPONSE_PARSE_FAILED,
    CSC_CONFIG_INVALID,
    CSC_NO_SIGNING_CREDENTIAL,
    CSC_NO_SIGNATURE_RETURNED,
    CSC_CERTIFICATE_UNPARSEABLE,
    CSC_MALFORMED_BASE64,
    CSC_PROBE_FAILED,
    SCAP_CREDENTIALS_INCOMPLETE,
    SCAP_CREDENTIALS_CONFIGURED,
    SCAP_ENVIRONMENT_SELECTOR_INVALID,
    SCAP_BASE_URL_UNSAFE,
    SCAP_BASE_URL_NOT_HTTPS,
    SCAP_BASE_URL_OK,
    SCAP_PROVIDER_CONFIGURATION_INVALID,
    SCAP_PROVIDERS_LISTED,
    SCAP_PROVIDER_LIST_FAILED,
    PKCS12_MATERIAL_INCOMPLETE,
    PKCS12_IDENTITY_UNDECRYPTABLE,
    PKCS12_IDENTITY_LOADED,
    PKCS12_CHALLENGE_SIGN_FAILED,
    PKCS12_CHALLENGE_SIGNED,
    PKCS12_CHALLENGE_VERIFIED,
    PKCS12_CHALLENGE_NOT_VERIFIED,
    AMA_CERT_PARSED,
    AMA_CERT_UNPARSEABLE,
    AMA_CERT_RSA_KEY_PRESENT,
    AMA_CERT_RSA_KEY_ABSENT,
    AMA_CERT_WITHIN_VALIDITY,
    AMA_CERT_EXPIRED,
    AMA_CERT_NOT_YET_VALID,
    AMA_CERT_VALIDITY_UNREADABLE,
    AMA_CERT_TRUST_NOT_ESTABLISHED,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_detail_code_is_unique() {
        let unique: BTreeSet<&&str> = ALL_PROBE_DETAIL_CODES.iter().collect();
        assert_eq!(
            unique.len(),
            ALL_PROBE_DETAIL_CODES.len(),
            "two checks share a detail code, so a client cannot tell their sentences apart"
        );
    }

    #[test]
    fn every_detail_code_is_a_lowercase_machine_identifier() {
        // These reach the client as map keys and are never translated; a stray space or capital
        // would make one un-typeable as a catalog-key suffix on the other side of the wire.
        for code in ALL_PROBE_DETAIL_CODES {
            assert!(
                !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "detail code {code:?} is not lower_snake_case ascii"
            );
        }
    }

    #[test]
    fn the_list_is_not_accidentally_empty_or_truncated() {
        // Non-vacuity: the web guard drives off this list, and an empty or halved list would make
        // that guard pass while proving nothing.
        assert!(
            ALL_PROBE_DETAIL_CODES.len() >= 83,
            "the detail-code list shrank to {}; deleting a code strands an older client's \
             translation, and the vocabulary is append-only",
            ALL_PROBE_DETAIL_CODES.len()
        );
    }
}
