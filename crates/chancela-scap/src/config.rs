//! SCAP configuration: environment (Preprod / Prod), base URL, credentials, provider filter.
//!
//! PROD without the required credential material must **fail closed** (mirrors the
//! `chancela-cmd` PROD-without-AMA-cert rejection in `chancela-cmd/src/config.rs`). The mock
//! transport needs no credentials; only the real HTTP transport does.

use zeroize::Zeroizing;

use crate::error::ScapError;

/// SCAP deployment environment. Selects the default endpoint and the credential policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScapEnvironment {
    /// AMA pre-production. Default; credentials optional (the mock needs none).
    Preprod,
    /// AMA production. Credentials are **mandatory** — a config without them fails closed.
    Prod,
}

/// Default PREPROD SCAP service base URL.
pub const PREPROD_BASE_URL: &str = "https://preprod.autenticacao.gov.pt/scap";
/// Default PROD SCAP service base URL.
pub const PROD_BASE_URL: &str = "https://autenticacao.gov.pt/scap";

impl ScapEnvironment {
    /// The default SCAP base URL for this environment.
    pub fn default_base_url(&self) -> &'static str {
        match self {
            ScapEnvironment::Preprod => PREPROD_BASE_URL,
            ScapEnvironment::Prod => PROD_BASE_URL,
        }
    }
}

/// AMA-issued credential material for the real SCAP HTTP transport.
///
/// Never committed and never logged: the `secret` is held in [`Zeroizing`] so it is scrubbed on
/// drop, and the [`std::fmt::Debug`] impl redacts both fields.
#[derive(Clone)]
pub struct ScapCredentials {
    /// Opaque AMA-assigned application/client identifier.
    pub application_id: String,
    /// The application secret / API key. Redacted in diagnostics and zeroized on drop.
    pub secret: Zeroizing<String>,
}

impl ScapCredentials {
    /// Build a credential pair.
    pub fn new(application_id: impl Into<String>, secret: impl Into<String>) -> Self {
        ScapCredentials {
            application_id: application_id.into(),
            secret: Zeroizing::new(secret.into()),
        }
    }
}

impl std::fmt::Debug for ScapCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScapCredentials")
            .field("application_id", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Static configuration for the SCAP client.
///
/// Built from env (`CHANCELA_SCAP_ENV`, `CHANCELA_SCAP_BASE_URL`,
/// `CHANCELA_SCAP_APPLICATION_ID`, `CHANCELA_SCAP_SECRET`, `CHANCELA_SCAP_PROVIDER_FILTER`) or
/// programmatically. `provider_filter`, when present, restricts attribute-provider listing to the
/// named provider ids.
#[derive(Clone)]
pub struct AmaScapConfig {
    /// Which AMA environment (preprod/prod) to talk to.
    pub environment: ScapEnvironment,
    /// The SCAP service base URL (defaults to the environment's URL when built via the helpers).
    pub base_url: String,
    /// Credential material — `None` for the mock; required (validated) for PROD HTTP.
    pub credentials: Option<ScapCredentials>,
    /// When set, restricts provider listing to these provider ids (empty = no filter).
    pub provider_filter: Option<Vec<String>>,
}

impl std::fmt::Debug for AmaScapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmaScapConfig")
            .field("environment", &self.environment)
            .field("base_url", &self.base_url)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "<configured>"),
            )
            .field("provider_filter", &self.provider_filter)
            .finish()
    }
}

impl AmaScapConfig {
    /// A preprod config with no credentials — the shape used with [`crate::MockScapTransport`].
    pub fn preprod() -> Self {
        AmaScapConfig {
            environment: ScapEnvironment::Preprod,
            base_url: PREPROD_BASE_URL.to_owned(),
            credentials: None,
            provider_filter: None,
        }
    }

    /// A prod config with the given credentials.
    pub fn prod(credentials: ScapCredentials) -> Self {
        AmaScapConfig {
            environment: ScapEnvironment::Prod,
            base_url: PROD_BASE_URL.to_owned(),
            credentials: Some(credentials),
            provider_filter: None,
        }
    }

    /// Restrict provider listing to the given provider ids.
    pub fn with_provider_filter(mut self, ids: impl IntoIterator<Item = String>) -> Self {
        self.provider_filter = Some(ids.into_iter().collect());
        self
    }

    /// Load config from the pinned env vars.
    ///
    /// - `CHANCELA_SCAP_ENV` = `preprod` | `prod` (default `preprod`).
    /// - `CHANCELA_SCAP_BASE_URL` (optional; overrides the environment default).
    /// - `CHANCELA_SCAP_APPLICATION_ID` + `CHANCELA_SCAP_SECRET` (optional in preprod; **required**
    ///   in prod — a prod config without them fails closed).
    /// - `CHANCELA_SCAP_PROVIDER_FILTER` (optional; comma-separated provider ids).
    pub fn from_env() -> Result<Self, ScapError> {
        Self::from_env_vars(|name| std::env::var(name).ok())
    }

    fn from_env_vars(get_var: impl Fn(&str) -> Option<String>) -> Result<Self, ScapError> {
        let environment = match get_var("CHANCELA_SCAP_ENV").as_deref() {
            Some("prod") | Some("PROD") | Some("Prod") => ScapEnvironment::Prod,
            Some("preprod") | Some("PREPROD") | Some("Preprod") | None => ScapEnvironment::Preprod,
            Some(other) => {
                return Err(ScapError::Config(format!(
                    "CHANCELA_SCAP_ENV must be 'preprod' or 'prod', got '{other}'"
                )));
            }
        };
        let base_url = env_var_nonempty(&get_var, "CHANCELA_SCAP_BASE_URL")
            .unwrap_or_else(|| environment.default_base_url().to_owned());
        let credentials = match (
            env_var_nonempty(&get_var, "CHANCELA_SCAP_APPLICATION_ID"),
            env_var_nonempty(&get_var, "CHANCELA_SCAP_SECRET"),
        ) {
            (Some(application_id), Some(secret)) => {
                Some(ScapCredentials::new(application_id, secret))
            }
            (None, None) => None,
            _ => {
                return Err(ScapError::Config(
                    "CHANCELA_SCAP_APPLICATION_ID and CHANCELA_SCAP_SECRET must be set together"
                        .to_owned(),
                ));
            }
        };
        let provider_filter =
            env_var_nonempty(&get_var, "CHANCELA_SCAP_PROVIDER_FILTER").map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            });
        let config = AmaScapConfig {
            environment,
            base_url,
            credentials,
            provider_filter,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate the invariants that always hold, regardless of transport.
    ///
    /// PROD **without** credentials is rejected — SCAP production requires AMA-issued credential
    /// material (mirrors the `chancela-cmd` PROD-without-AMA-cert rejection; t67 §6). The mock
    /// transport is exempt because it is only ever used with a preprod config.
    pub fn validate(&self) -> Result<(), ScapError> {
        if self.base_url.trim().is_empty() {
            return Err(ScapError::Config("base_url must not be empty".to_owned()));
        }
        if matches!(self.environment, ScapEnvironment::Prod) && self.credentials.is_none() {
            return Err(ScapError::Config(
                "PROD requires CHANCELA_SCAP_APPLICATION_ID and CHANCELA_SCAP_SECRET \
                 (SCAP production credentials are mandatory)"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate requirements specific to the real HTTP transport: credentials must be present in
    /// **either** environment (the mock is the only credential-free path).
    pub fn validate_http_transport(&self) -> Result<(), ScapError> {
        self.validate()?;
        if self.credentials.is_none() {
            return Err(ScapError::Config(
                "the SCAP HTTP transport requires CHANCELA_SCAP_APPLICATION_ID and \
                 CHANCELA_SCAP_SECRET; use the mock transport for credential-free testing"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

fn env_var_nonempty(get_var: &impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    get_var(name).filter(|v| !v.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_from_pairs(pairs: &[(&str, &str)]) -> Result<AmaScapConfig, ScapError> {
        AmaScapConfig::from_env_vars(|name| {
            pairs
                .iter()
                .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
        })
    }

    #[test]
    fn preprod_helper_needs_no_credentials() {
        let cfg = AmaScapConfig::preprod();
        assert_eq!(cfg.environment, ScapEnvironment::Preprod);
        assert!(cfg.credentials.is_none());
        cfg.validate()
            .expect("preprod without credentials is valid");
    }

    #[test]
    fn prod_without_credentials_fails_closed() {
        let cfg = AmaScapConfig {
            environment: ScapEnvironment::Prod,
            base_url: PROD_BASE_URL.to_owned(),
            credentials: None,
            provider_filter: None,
        };
        let err = cfg.validate().unwrap_err();
        match err {
            ScapError::Config(msg) => assert!(msg.contains("PROD requires")),
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn from_env_prod_without_credentials_fails_closed() {
        let err = load_from_pairs(&[("CHANCELA_SCAP_ENV", "prod")]).unwrap_err();
        match err {
            ScapError::Config(msg) => assert!(msg.contains("PROD requires")),
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn from_env_rejects_partial_credentials() {
        let err = load_from_pairs(&[("CHANCELA_SCAP_APPLICATION_ID", "app-123")]).unwrap_err();
        match err {
            ScapError::Config(msg) => {
                assert!(msg.contains("CHANCELA_SCAP_APPLICATION_ID"));
                assert!(msg.contains("CHANCELA_SCAP_SECRET"));
                assert!(!msg.contains("app-123"));
            }
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn from_env_loads_prod_credentials_and_filter() {
        let cfg = load_from_pairs(&[
            ("CHANCELA_SCAP_ENV", "prod"),
            ("CHANCELA_SCAP_APPLICATION_ID", "app-123"),
            ("CHANCELA_SCAP_SECRET", "s3cr3t"),
            ("CHANCELA_SCAP_PROVIDER_FILTER", "oa, oe ,"),
        ])
        .unwrap();
        assert_eq!(cfg.environment, ScapEnvironment::Prod);
        assert_eq!(cfg.base_url, PROD_BASE_URL);
        let creds = cfg.credentials.as_ref().unwrap();
        assert_eq!(creds.application_id, "app-123");
        assert_eq!(creds.secret.as_str(), "s3cr3t");
        assert_eq!(cfg.provider_filter.unwrap(), vec!["oa", "oe"]);
    }

    #[test]
    fn validate_http_transport_requires_credentials_even_in_preprod() {
        let cfg = AmaScapConfig::preprod();
        let err = cfg.validate_http_transport().unwrap_err();
        match err {
            ScapError::Config(msg) => assert!(msg.contains("HTTP transport requires")),
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn credentials_are_redacted_in_debug() {
        let cfg = AmaScapConfig::prod(ScapCredentials::new("app-SECRET", "SUPER-SECRET"));
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("app-SECRET"));
        assert!(!debug.contains("SUPER-SECRET"));
        assert!(debug.contains("<configured>"));

        let creds_debug = format!("{:?}", ScapCredentials::new("app-SECRET", "SUPER-SECRET"));
        assert!(!creds_debug.contains("app-SECRET"));
        assert!(!creds_debug.contains("SUPER-SECRET"));
        assert!(creds_debug.contains("<redacted>"));
    }
}
