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
    /// AMA pre-production (`preprod.cmd.autenticacao.gov.pt`). The real HTTP transport requires
    /// field encryption in every environment (see [`CmdConfig::validate_http_transport`]).
    Preprod,
    /// AMA production (`cmd.autenticacao.gov.pt`). Field encryption required.
    Prod,
}

/// PROD `AppSCMDService.svc` endpoint.
///
/// **Provenance — proven.** recov-pt (`F:\Projects\recov-pt`), the working reference that completes
/// the full CMD flow against the live service, targets exactly this URL
/// (`recov-pt/src/cli/scanner.rs:15`). This value is trusted because a working tool uses it.
pub const PROD_ENDPOINT: &str =
    "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/AppSCMDService.svc";
/// PREPROD `AppSCMDService.svc` endpoint.
///
/// **Provenance — documented-by-convention, UNVERIFIED here.** No in-tree source names a preprod
/// host for `AppSCMDService.svc`. This URL is composed from two documented parts: the `preprod.`
/// host prefix + `Ama.Authentication.Frontend` path are AMA's documented pre-production convention
/// (bundled middleware
/// `autenticacao.gov-3.15.0/pteid-mw-pt/_src/eidmw/CMD/services/CCMovelDigitalSignature.h:1180`,
/// which documents preprod for the older SOAP service on the same host family), and the
/// `AppSCMDService.svc` service segment is the working prod generation's
/// (`recov-pt/src/cli/scanner.rs:15`). It is therefore *documented-but-not-verified-here*: unlike
/// prod, no live call has confirmed it. Swap it for the exact value if a doc names one directly.
pub const PREPROD_ENDPOINT: &str =
    "https://preprod.cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/AppSCMDService.svc";

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
/// AMA-assigned string, sent as the **raw** string on the wire — never base64-encoded (recov-pt
/// `src/cli/cmd_verify.rs:1097`; conformance vector `tests/conformance_vectors.rs`). `basic_auth`
/// is used only by the real HTTP transport; `ama_cert_pem` is the PEM text of AMA's
/// field-encryption certificate when field encryption is used.
#[derive(Clone)]
pub struct CmdConfig {
    /// Which AMA environment (preprod/prod) to talk to.
    pub env: CmdEnv,
    /// Opaque AMA-assigned ApplicationId, sent as the raw string on the wire (never base64).
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
            (Some(pem), _) => FieldEncryptor::from_ama_key_pem(pem),
            (None, CmdEnv::Preprod) => Ok(FieldEncryptor::Cleartext),
            (None, CmdEnv::Prod) => Err(CmdError::Config(
                "PROD requires CHANCELA_CMD_AMA_CERT_PEM (field encryption is mandatory)"
                    .to_string(),
            )),
        }
    }

    /// Validate requirements that apply only to the real HTTP transport.
    ///
    /// Mock transports may run with just an `ApplicationId`, but a real call to the SCMD JSON
    /// service needs AMA field encryption in **every** environment, plus HTTP BasicAuth in
    /// production.
    ///
    /// **Field encryption is mandatory on the real transport, preprod included.** The working
    /// reference (recov-pt) always RSA-encrypts the mobile/PIN/OTP, and the service rejects
    /// cleartext; a cleartext HTTP client would only ever build a request the service refuses. So a
    /// transport without an AMA certificate is refused here rather than silently sending cleartext
    /// that fails on the wire. The offline [`crate::mock::MockScmdTransport`] path
    /// ([`crate::ScmdClient::new`]) may still run [`FieldEncryptor::Cleartext`] because it never
    /// reaches the service; this gate is what keeps that mode off the real JSON path.
    pub fn validate_http_transport(&self) -> Result<(), CmdError> {
        if self.ama_cert_pem.is_none() {
            return Err(CmdError::Config(
                "CMD HTTP transport requires an AMA field-encryption certificate (field encryption \
                 is mandatory on the SCMD service): set CHANCELA_CMD_AMA_CERT_PEM or the credential's \
                 ama_cert_pem"
                    .to_string(),
            ));
        }
        // Also validates that the certificate parses into an RSA encryptor.
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
