//! [`CmdConfig`] — environment selection, `ApplicationId`, optional HTTP BasicAuth,
//! and the optional AMA field-encryption certificate. Env-var names are pinned here and
//! documented in `TESTING.md`.

use crate::error::CmdError;
use crate::field_encryption::FieldEncryptor;
use zeroize::Zeroizing;

/// SCMD deployment environment. Selects the endpoint (§1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CmdEnv {
    /// AMA pre-production (`preprod.cmd.autenticacao.gov.pt`). Default; cleartext fields allowed.
    Preprod,
    /// AMA production (`cmd.autenticacao.gov.pt`). Field encryption required.
    Prod,
}

/// PREPROD `CCMovelDigitalSignature.svc` endpoint (spec 04 §1.3).
pub const PREPROD_ENDPOINT: &str = "https://preprod.cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";
/// PROD `CCMovelDigitalSignature.svc` endpoint (spec 04 §1.3).
pub const PROD_ENDPOINT: &str =
    "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";

impl CmdEnv {
    /// The SCMD service endpoint URL for this environment.
    pub fn endpoint(&self) -> &'static str {
        match self {
            CmdEnv::Preprod => PREPROD_ENDPOINT,
            CmdEnv::Prod => PROD_ENDPOINT,
        }
    }
}

/// HTTP BasicAuth credentials for the real AMA transport.
///
/// Some AMA environments accept unauthenticated preprod calls, but production integrations
/// require BasicAuth in addition to the SCMD `ApplicationId` carried in SOAP payloads.
#[derive(Clone)]
pub struct CmdBasicAuth {
    /// AMA-issued HTTP BasicAuth username.
    pub username: String,
    /// AMA-issued HTTP BasicAuth password. Redacted in diagnostics and zeroized on drop.
    pub password: Zeroizing<String>,
}

impl CmdBasicAuth {
    /// Build a BasicAuth credential pair.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        CmdBasicAuth {
            username: username.into(),
            password: Zeroizing::new(password.into()),
        }
    }
}

impl std::fmt::Debug for CmdBasicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmdBasicAuth")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Static configuration for the SCMD client.
///
/// Built from env (`CHANCELA_CMD_ENV`, `CHANCELA_CMD_APPLICATION_ID`,
/// `CHANCELA_CMD_HTTP_BASIC_USERNAME`, `CHANCELA_CMD_HTTP_BASIC_PASSWORD`,
/// `CHANCELA_CMD_AMA_CERT_PEM`) or programmatically. The `application_id` is the opaque
/// AMA-assigned string (sent UTF-8 -> base64 on the wire); `basic_auth` is used only by
/// the real HTTP transport; `ama_cert_pem` is the PEM text of AMA's field-encryption
/// certificate when field encryption is used.
#[derive(Clone)]
pub struct CmdConfig {
    /// Which AMA environment (preprod/prod) to talk to.
    pub env: CmdEnv,
    /// Opaque AMA-assigned ApplicationId (base64-encoded on the wire).
    pub application_id: String,
    /// Optional HTTP BasicAuth credentials for [`crate::transport::HttpScmdTransport`].
    pub basic_auth: Option<CmdBasicAuth>,
    /// PEM text of AMA's field-encryption certificate (None => cleartext, preprod only).
    pub ama_cert_pem: Option<String>,
}

impl std::fmt::Debug for CmdConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmdConfig")
            .field("env", &self.env)
            .field("application_id", &"<redacted>")
            .field("basic_auth", &self.basic_auth)
            .field(
                "ama_cert_pem",
                &self.ama_cert_pem.as_ref().map(|_| "<configured>"),
            )
            .finish()
    }
}

impl CmdConfig {
    /// A preprod config with the given ApplicationId and no field encryption (cleartext).
    pub fn preprod(application_id: impl Into<String>) -> Self {
        CmdConfig {
            env: CmdEnv::Preprod,
            application_id: application_id.into(),
            basic_auth: None,
            ama_cert_pem: None,
        }
    }

    /// Load config from the pinned env vars (§2.3).
    ///
    /// - `CHANCELA_CMD_ENV` = `preprod` | `prod` (default `preprod`).
    /// - `CHANCELA_CMD_APPLICATION_ID` (required).
    /// - `CHANCELA_CMD_HTTP_BASIC_USERNAME` + `CHANCELA_CMD_HTTP_BASIC_PASSWORD`
    ///   (optional in preprod; required by [`crate::transport::HttpScmdTransport`] in prod).
    /// - `CHANCELA_CMD_AMA_CERT_PEM` = path to AMA cert PEM (optional; read into memory).
    pub fn from_env() -> Result<Self, CmdError> {
        Self::from_env_vars(
            |name| std::env::var(name).ok(),
            |path| std::fs::read_to_string(path),
        )
    }

    fn from_env_vars(
        get_var: impl Fn(&str) -> Option<String>,
        read_to_string: impl Fn(&str) -> Result<String, std::io::Error>,
    ) -> Result<Self, CmdError> {
        let env = match get_var("CHANCELA_CMD_ENV").as_deref() {
            Some("prod") | Some("PROD") | Some("Prod") => CmdEnv::Prod,
            Some("preprod") | Some("PREPROD") | Some("Preprod") | None => CmdEnv::Preprod,
            Some(other) => {
                return Err(CmdError::Config(format!(
                    "CHANCELA_CMD_ENV must be 'preprod' or 'prod', got '{other}'"
                )));
            }
        };
        let application_id = get_var("CHANCELA_CMD_APPLICATION_ID").ok_or_else(|| {
            CmdError::Config("CHANCELA_CMD_APPLICATION_ID is not set".to_string())
        })?;
        if application_id.trim().is_empty() {
            return Err(CmdError::Config(
                "CHANCELA_CMD_APPLICATION_ID must not be empty".to_string(),
            ));
        }
        let basic_auth = match (
            env_var_nonempty(&get_var, "CHANCELA_CMD_HTTP_BASIC_USERNAME"),
            env_var_nonempty(&get_var, "CHANCELA_CMD_HTTP_BASIC_PASSWORD"),
        ) {
            (Some(username), Some(password)) => Some(CmdBasicAuth::new(username, password)),
            (None, None) => None,
            _ => {
                return Err(CmdError::Config(
                    "CHANCELA_CMD_HTTP_BASIC_USERNAME and CHANCELA_CMD_HTTP_BASIC_PASSWORD must be set together".to_string(),
                ));
            }
        };
        let ama_cert_pem = match get_var("CHANCELA_CMD_AMA_CERT_PEM") {
            Some(path) if !path.is_empty() => Some(read_to_string(&path).map_err(|e| {
                CmdError::Config(format!(
                    "failed to read CHANCELA_CMD_AMA_CERT_PEM '{path}': {e}"
                ))
            })?),
            _ => None,
        };
        Ok(CmdConfig {
            env,
            application_id,
            basic_auth,
            ama_cert_pem,
        })
    }

    /// The SCMD endpoint URL for the configured environment.
    pub fn endpoint(&self) -> &'static str {
        self.env.endpoint()
    }

    /// Build the [`FieldEncryptor`] this config implies.
    ///
    /// If an AMA cert is present, sensitive fields (phone, PIN, OTP) are RSA-encrypted;
    /// otherwise cleartext. PROD **without** an AMA cert is rejected — PROD requires
    /// field encryption (spec 04 §1.3 / risk #6).
    pub fn field_encryptor(&self) -> Result<FieldEncryptor, CmdError> {
        match (&self.ama_cert_pem, self.env) {
            (Some(pem), _) => FieldEncryptor::from_ama_cert_pem(pem),
            (None, CmdEnv::Preprod) => Ok(FieldEncryptor::Cleartext),
            (None, CmdEnv::Prod) => Err(CmdError::Config(
                "PROD requires CHANCELA_CMD_AMA_CERT_PEM (field encryption is mandatory)"
                    .to_string(),
            )),
        }
    }

    /// Validate requirements that apply only to the real HTTP transport.
    ///
    /// Mock transports may run with just an `ApplicationId`, but production HTTP calls need
    /// both AMA field encryption and HTTP BasicAuth credentials.
    pub fn validate_http_transport(&self) -> Result<(), CmdError> {
        self.field_encryptor()?;
        if matches!(self.env, CmdEnv::Prod) && self.basic_auth.is_none() {
            return Err(CmdError::Config(
                "PROD HTTP transport requires CHANCELA_CMD_HTTP_BASIC_USERNAME and CHANCELA_CMD_HTTP_BASIC_PASSWORD".to_string(),
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

    fn load_from_pairs(pairs: &[(&str, &str)]) -> Result<CmdConfig, CmdError> {
        CmdConfig::from_env_vars(
            |name| {
                pairs
                    .iter()
                    .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
            },
            |_| Ok::<String, std::io::Error>("CERT-PEM".to_string()),
        )
    }

    #[test]
    fn from_env_loads_basic_auth_pair() {
        let cfg = load_from_pairs(&[
            ("CHANCELA_CMD_APPLICATION_ID", "APPID"),
            ("CHANCELA_CMD_HTTP_BASIC_USERNAME", "ama-user"),
            ("CHANCELA_CMD_HTTP_BASIC_PASSWORD", "ama-password"),
        ])
        .unwrap();

        let auth = cfg.basic_auth.unwrap();
        assert_eq!(cfg.env, CmdEnv::Preprod);
        assert_eq!(auth.username, "ama-user");
        assert_eq!(auth.password.as_str(), "ama-password");
    }

    #[test]
    fn from_env_rejects_partial_basic_auth() {
        let err = load_from_pairs(&[
            ("CHANCELA_CMD_APPLICATION_ID", "APPID"),
            ("CHANCELA_CMD_HTTP_BASIC_USERNAME", "ama-user"),
        ])
        .unwrap_err();
        match err {
            CmdError::Config(msg) => {
                assert!(msg.contains("CHANCELA_CMD_HTTP_BASIC_USERNAME"));
                assert!(msg.contains("CHANCELA_CMD_HTTP_BASIC_PASSWORD"));
                assert!(!msg.contains("ama-user"));
            }
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[test]
    fn diagnostics_redact_sensitive_values() {
        let cfg = CmdConfig {
            env: CmdEnv::Prod,
            application_id: "APPID-SECRET".to_string(),
            basic_auth: Some(CmdBasicAuth::new("ama-user", "ama-password")),
            ama_cert_pem: Some("CERT-PEM".to_string()),
        };

        let debug = format!("{cfg:?}");
        assert!(!debug.contains("APPID-SECRET"));
        assert!(!debug.contains("ama-user"));
        assert!(!debug.contains("ama-password"));
        assert!(!debug.contains("CERT-PEM"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("<configured>"));
    }

    #[test]
    fn prod_http_transport_requires_basic_auth() {
        let cfg = CmdConfig {
            env: CmdEnv::Prod,
            application_id: "APPID".to_string(),
            basic_auth: None,
            ama_cert_pem: Some(include_str!("../fixtures/ama_encryption_cert.pem").to_string()),
        };

        let err = cfg.validate_http_transport().unwrap_err();
        match err {
            CmdError::Config(msg) => {
                assert!(msg.contains("PROD HTTP transport requires"));
                assert!(msg.contains("CHANCELA_CMD_HTTP_BASIC_USERNAME"));
            }
            other => panic!("expected config error, got {other:?}"),
        }
    }
}
