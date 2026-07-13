//! [`CscConfig`] — the **non-secret** per-provider selectors (base URL, provider id,
//! authorization model, sandbox flag, optional pre-selected credential) that a settings
//! document surfaces, and [`CscSecrets`] — the OAuth client credentials / access token loaded from
//! the environment or assembled from an already-decrypted protected runtime store.
//!
//! The api provider registry (t59 Slice 3) builds a [`CscConfig`] from settings and a
//! [`CscSecrets`] from `CHANCELA_CSC_<PROVIDER>_*` env vars or protected runtime credentials, then
//! constructs a [`CscRemoteSource`](crate::CscRemoteSource). The settings document only ever holds
//! the [`CscProviderInfo`] projection — never a secret.

use zeroize::Zeroizing;

use crate::error::CscError;

/// The default OAuth2 scope for CSC service-level authentication.
pub const DEFAULT_SCOPE: &str = "service";

/// The CSC authorization model a provider uses (t59 P-E).
///
/// This selects *how the signature is authorized*, not whether it is qualified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CscAuthorization {
    /// Service-level: the platform holds one OAuth client credential and drives the credential's
    /// signature-activation (OTP/SAD) on the signer's behalf (`client_credentials` grant).
    Service,
    /// User-level: the signer authenticates to the QTSP out-of-band (OAuth authorization-code /
    /// the provider's app) and the platform is handed a short-lived access token
    /// ([`CscSecrets::access_token`]).
    User,
}

impl CscAuthorization {
    /// The lower-case wire/settings token for this model (`"service"` | `"user"`).
    pub fn as_str(self) -> &'static str {
        match self {
            CscAuthorization::Service => "service",
            CscAuthorization::User => "user",
        }
    }

    /// Parse the settings token (`"service"` | `"user"`).
    pub fn parse(s: &str) -> Result<Self, CscError> {
        match s {
            "service" => Ok(CscAuthorization::Service),
            "user" => Ok(CscAuthorization::User),
            other => Err(CscError::Config(format!(
                "authorization must be 'service' or 'user', got '{other}'"
            ))),
        }
    }
}

/// Static, **non-secret** configuration for a CSC provider (t59 F2/F3).
///
/// Every field here is safe to persist in the settings document. Secrets live in [`CscSecrets`],
/// loaded from the environment or protected provider-credential storage.
#[derive(Debug, Clone)]
pub struct CscConfig {
    /// The stable provider id stamped onto the produced session/artifact (e.g. `"multicert"`,
    /// `"digitalsign"`). Lower-case, ascii; used to derive the env-var prefix.
    pub provider_id: String,
    /// Human-readable provider name for the UI picker (e.g. `"Multicert"`).
    pub display_name: String,
    /// The provider's CSC v2 API base URL (e.g. `https://sandbox.qtsp.example/csc/v2/`). A
    /// trailing slash is optional; request paths are joined defensively.
    pub base_url: String,
    /// The authorization model (t59 P-E).
    pub authorization: CscAuthorization,
    /// Whether this points at the provider's sandbox/preprod (defaults true; real signing is an
    /// ops step gated on per-provider onboarding).
    pub sandbox: bool,
    /// An optional pre-selected credential id. When `None`, `initiate` resolves it via
    /// `credentials/list` (choosing the sole credential, or erroring if ambiguous/empty).
    pub credential_id: Option<String>,
    /// The OAuth2 scope requested for service-level authentication (default [`DEFAULT_SCOPE`]).
    pub scope: String,
}

impl CscConfig {
    /// A sandbox, service-authorization config for `provider_id` at `base_url`.
    pub fn sandbox(
        provider_id: impl Into<String>,
        display_name: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        CscConfig {
            provider_id: provider_id.into(),
            display_name: display_name.into(),
            base_url: base_url.into(),
            authorization: CscAuthorization::Service,
            sandbox: true,
            credential_id: None,
            scope: DEFAULT_SCOPE.to_string(),
        }
    }

    /// Validate the config shape (non-empty ids, an `https` base URL). Sandbox is exempt from the
    /// `https` requirement only for a `http://localhost`/`http://127.0.0.1` test endpoint.
    pub fn validate(&self) -> Result<(), CscError> {
        if self.provider_id.trim().is_empty() {
            return Err(CscError::Config(
                "provider_id must not be empty".to_string(),
            ));
        }
        let url = self.base_url.trim();
        let is_https = url.starts_with("https://");
        let is_local = url.starts_with("http://localhost") || url.starts_with("http://127.0.0.1");
        if !(is_https || (self.sandbox && is_local)) {
            return Err(CscError::Config(format!(
                "base_url for provider '{}' must be https (got '{}')",
                self.provider_id, url
            )));
        }
        Ok(())
    }

    /// The non-secret projection surfaced to the settings document / UI picker.
    pub fn provider_info(&self, credentials_configured: bool) -> CscProviderInfo {
        CscProviderInfo {
            provider_id: self.provider_id.clone(),
            display_name: self.display_name.clone(),
            authorization: self.authorization,
            sandbox: self.sandbox,
            credentials_configured,
        }
    }

    /// The upper-cased env-var prefix for this provider's secrets
    /// (`CHANCELA_CSC_<PROVIDER>_…`). Non-alphanumeric characters become `_`.
    pub fn env_prefix(&self) -> String {
        env_prefix(&self.provider_id)
    }
}

/// The env-var prefix (`CHANCELA_CSC_<PROVIDER>`) for a provider id.
fn env_prefix(provider_id: &str) -> String {
    let sanitized: String = provider_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("CHANCELA_CSC_{sanitized}")
}

/// The **secret** per-provider credentials. Never serialized, never logged; held in [`Zeroizing`]
/// buffers so they are wiped from memory on drop.
///
/// Env vars (per provider `<P>` = the upper-cased provider id):
/// - `CHANCELA_CSC_<P>_CLIENT_ID` / `_CLIENT_SECRET` — the OAuth2 client credential
///   (service authorization).
/// - `CHANCELA_CSC_<P>_ACCESS_TOKEN` — a pre-obtained bearer token (user authorization).
#[derive(Clone)]
pub struct CscSecrets {
    /// OAuth2 client id (service authorization).
    pub client_id: Zeroizing<String>,
    /// OAuth2 client secret (service authorization).
    pub client_secret: Zeroizing<String>,
    /// A pre-obtained bearer access token (user authorization; supplied out-of-band).
    pub access_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for CscSecrets {
    /// Redacts every field — a secret must never leak through `Debug`/logging (t59 §6).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CscSecrets")
            .field("client_id", &"<redacted>")
            .field("client_secret", &"<redacted>")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl CscSecrets {
    /// Construct secrets directly (tests / programmatic).
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        CscSecrets {
            client_id: Zeroizing::new(client_id.into()),
            client_secret: Zeroizing::new(client_secret.into()),
            access_token: None,
        }
    }

    /// A user-authorization secret carrying a pre-obtained bearer access token.
    pub fn with_access_token(token: impl Into<String>) -> Self {
        CscSecrets {
            client_id: Zeroizing::new(String::new()),
            client_secret: Zeroizing::new(String::new()),
            access_token: Some(Zeroizing::new(token.into())),
        }
    }

    /// Construct secrets from already-materialized fields using the same completeness rules as the
    /// environment loader: either `client_id + client_secret` for service authorization, or
    /// `access_token` by itself for user authorization. Partial combinations are rejected without
    /// including any field values in the error.
    pub fn from_parts(
        provider_id: &str,
        client_id: Option<Zeroizing<String>>,
        client_secret: Option<Zeroizing<String>>,
        access_token: Option<Zeroizing<String>>,
    ) -> Result<Self, CscError> {
        let client_id = nonblank_secret(client_id);
        let client_secret = nonblank_secret(client_secret);
        let access_token = nonblank_secret(access_token);
        match (client_id, client_secret, access_token) {
            (Some(client_id), Some(client_secret), access_token) => Ok(CscSecrets {
                client_id,
                client_secret,
                access_token,
            }),
            (None, None, Some(access_token)) => Ok(CscSecrets {
                client_id: Zeroizing::new(String::new()),
                client_secret: Zeroizing::new(String::new()),
                access_token: Some(access_token),
            }),
            _ => Err(CscError::Config(format!(
                "provider '{provider_id}' is not configured: set client_id + client_secret \
                 (service) or access_token (user)"
            ))),
        }
    }

    /// Load the secrets for `provider_id` from `CHANCELA_CSC_<PROVIDER>_*` env vars.
    ///
    /// Requires either a client id + secret (service) or an access token (user); errors if
    /// neither is present.
    pub fn from_env(provider_id: &str) -> Result<Self, CscError> {
        let prefix = env_prefix(provider_id);
        let get = |suffix: &str| -> Option<String> {
            std::env::var(format!("{prefix}_{suffix}"))
                .ok()
                .filter(|v| !v.trim().is_empty())
        };
        let client_id = get("CLIENT_ID");
        let client_secret = get("CLIENT_SECRET");
        let access_token = get("ACCESS_TOKEN");
        Self::from_parts(
            provider_id,
            client_id.map(Zeroizing::new),
            client_secret.map(Zeroizing::new),
            access_token.map(Zeroizing::new),
        )
        .map_err(|_| {
            CscError::Config(format!(
                "provider '{provider_id}' is not configured: set {prefix}_CLIENT_ID + \
                 {prefix}_CLIENT_SECRET (service) or {prefix}_ACCESS_TOKEN (user)"
            ))
        })
    }

    /// Whether `provider_id`'s env-var secrets are present. Settings provider status also combines
    /// this with protected provider-credential storage so `credentials_configured` reflects
    /// protected storage or environment — never the secret itself.
    pub fn is_configured(provider_id: &str) -> bool {
        Self::from_env(provider_id).is_ok()
    }
}

fn nonblank_secret(secret: Option<Zeroizing<String>>) -> Option<Zeroizing<String>> {
    secret.filter(|value| !value.trim().is_empty())
}

/// The non-secret provider projection for the settings document / UI picker (t59 F3/F4).
///
/// Deliberately carries **no** secret and no base URL secret material — only what the picker
/// and settings surface need. `credentials_configured` is a read-only boolean derived from the
/// runtime credential source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CscProviderInfo {
    /// Stable provider id.
    pub provider_id: String,
    /// Human-readable name for the picker.
    pub display_name: String,
    /// The authorization model.
    pub authorization: CscAuthorization,
    /// Whether this is a sandbox endpoint.
    pub sandbox: bool,
    /// Whether runtime credentials are configured through environment or protected storage.
    pub credentials_configured: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    #[test]
    fn from_parts_accepts_service_client_credentials() {
        let secrets = CscSecrets::from_parts(
            "encosto-qtsp",
            Some(secret("client-id-fixture")),
            Some(secret("client-secret-fixture")),
            None,
        )
        .expect("service credentials are complete");

        assert_eq!(secrets.client_id.as_str(), "client-id-fixture");
        assert_eq!(secrets.client_secret.as_str(), "client-secret-fixture");
        assert!(secrets.access_token.is_none());
    }

    #[test]
    fn from_parts_accepts_access_token_only() {
        let secrets = CscSecrets::from_parts(
            "encosto-qtsp",
            None,
            None,
            Some(secret("access-token-fixture")),
        )
        .expect("access token credentials are complete");

        assert_eq!(secrets.client_id.as_str(), "");
        assert_eq!(secrets.client_secret.as_str(), "");
        assert_eq!(
            secrets.access_token.as_ref().map(|token| token.as_str()),
            Some("access-token-fixture")
        );
    }

    #[test]
    fn from_parts_rejects_partial_service_credentials_without_values() {
        let err = CscSecrets::from_parts(
            "encosto-qtsp",
            Some(secret("client-id-fixture")),
            None,
            None,
        )
        .expect_err("partial service credentials are rejected");
        let msg = err.to_string();

        assert!(msg.contains("client_id"));
        assert!(msg.contains("client_secret"));
        assert!(msg.contains("access_token"));
        assert!(!msg.contains("client-id-fixture"));
    }

    #[test]
    fn from_parts_rejects_blank_service_secret_as_missing() {
        let err = CscSecrets::from_parts(
            "encosto-qtsp",
            Some(secret("client-id-fixture")),
            Some(secret("   ")),
            None,
        )
        .expect_err("blank service secret is rejected");
        let msg = err.to_string();

        assert!(msg.contains("client_secret"));
        assert!(!msg.contains("client-id-fixture"));
    }

    #[test]
    fn from_parts_rejects_blank_access_token_as_missing() {
        let err = CscSecrets::from_parts("encosto-qtsp", None, None, Some(secret("\t")))
            .expect_err("blank access token is rejected");
        let msg = err.to_string();

        assert!(msg.contains("access_token"));
    }
}
