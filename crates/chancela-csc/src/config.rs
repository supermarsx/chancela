//! [`CscConfig`] — the **non-secret** per-provider selectors (base URL, provider id,
//! authorization model, sandbox flag, optional pre-selected credential) that a settings
//! document surfaces, and [`CscSecrets`] — the OAuth client credentials / access token loaded
//! **exclusively from the environment** (t59 ruling 5; never JSON, never persisted).
//!
//! The api provider registry (t59 Slice 3) builds a [`CscConfig`] from settings and a
//! [`CscSecrets`] from `CHANCELA_CSC_<PROVIDER>_*` env vars, then constructs a
//! [`CscRemoteSource`](crate::CscRemoteSource). The settings document only ever holds the
//! [`CscProviderInfo`] projection — never a secret.

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
/// Every field here is safe to persist in the settings document. Secrets live in
/// [`CscSecrets`], loaded from the environment.
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

/// The **secret** per-provider credentials, loaded exclusively from the environment
/// (t59 ruling 5). Never serialized, never logged; held in [`Zeroizing`] buffers so they are
/// wiped from memory on drop.
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

    /// Load the secrets for `provider_id` from `CHANCELA_CSC_<PROVIDER>_*` env vars.
    ///
    /// Requires either a client id + secret (service) or an access token (user); errors if
    /// neither is present.
    pub fn from_env(provider_id: &str) -> Result<Self, CscError> {
        let prefix = env_prefix(provider_id);
        let get = |suffix: &str| -> Option<String> {
            std::env::var(format!("{prefix}_{suffix}"))
                .ok()
                .filter(|v| !v.is_empty())
        };
        let client_id = get("CLIENT_ID");
        let client_secret = get("CLIENT_SECRET");
        let access_token = get("ACCESS_TOKEN");
        match (client_id, client_secret, access_token) {
            (Some(id), Some(secret), token) => Ok(CscSecrets {
                client_id: Zeroizing::new(id),
                client_secret: Zeroizing::new(secret),
                access_token: token.map(Zeroizing::new),
            }),
            (None, None, Some(token)) => Ok(CscSecrets::with_access_token(token)),
            _ => Err(CscError::Config(format!(
                "provider '{provider_id}' is not configured: set {prefix}_CLIENT_ID + \
                 {prefix}_CLIENT_SECRET (service) or {prefix}_ACCESS_TOKEN (user)"
            ))),
        }
    }

    /// Whether `provider_id`'s secrets are present in the environment (the read-only
    /// `credentials_configured` flag surfaced to settings — never the secret itself).
    pub fn is_configured(provider_id: &str) -> bool {
        Self::from_env(provider_id).is_ok()
    }
}

/// The non-secret provider projection for the settings document / UI picker (t59 F3/F4).
///
/// Deliberately carries **no** secret and no base URL secret material — only what the picker
/// and settings surface need. `credentials_configured` is a read-only boolean derived from the
/// environment ([`CscSecrets::is_configured`]).
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
    /// Whether the provider's secrets are present in the environment (read-only).
    pub credentials_configured: bool,
}
