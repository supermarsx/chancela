//! [`CmdConfig`] — environment selection, `ApplicationId`, and the optional AMA
//! field-encryption certificate. Env-var names are pinned in `.orchestration/plans/t4.md` §2.3.

use crate::error::CmdError;
use crate::field_encryption::FieldEncryptor;

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

/// Static configuration for the SCMD client.
///
/// Built from env (`CHANCELA_CMD_ENV`, `CHANCELA_CMD_APPLICATION_ID`,
/// `CHANCELA_CMD_AMA_CERT_PEM`) or programmatically. The `application_id` is the
/// opaque AMA-assigned string (sent UTF-8 -> base64 on the wire); `ama_cert_pem`
/// is the PEM text of AMA's field-encryption certificate when field encryption is used.
#[derive(Debug, Clone)]
pub struct CmdConfig {
    /// Which AMA environment (preprod/prod) to talk to.
    pub env: CmdEnv,
    /// Opaque AMA-assigned ApplicationId (base64-encoded on the wire).
    pub application_id: String,
    /// PEM text of AMA's field-encryption certificate (None => cleartext, preprod only).
    pub ama_cert_pem: Option<String>,
}

impl CmdConfig {
    /// A preprod config with the given ApplicationId and no field encryption (cleartext).
    pub fn preprod(application_id: impl Into<String>) -> Self {
        CmdConfig {
            env: CmdEnv::Preprod,
            application_id: application_id.into(),
            ama_cert_pem: None,
        }
    }

    /// Load config from the pinned env vars (§2.3).
    ///
    /// - `CHANCELA_CMD_ENV` = `preprod` | `prod` (default `preprod`).
    /// - `CHANCELA_CMD_APPLICATION_ID` (required).
    /// - `CHANCELA_CMD_AMA_CERT_PEM` = path to AMA cert PEM (optional; read into memory).
    pub fn from_env() -> Result<Self, CmdError> {
        let env = match std::env::var("CHANCELA_CMD_ENV").ok().as_deref() {
            Some("prod") | Some("PROD") | Some("Prod") => CmdEnv::Prod,
            Some("preprod") | Some("PREPROD") | Some("Preprod") | None => CmdEnv::Preprod,
            Some(other) => {
                return Err(CmdError::Config(format!(
                    "CHANCELA_CMD_ENV must be 'preprod' or 'prod', got '{other}'"
                )));
            }
        };
        let application_id = std::env::var("CHANCELA_CMD_APPLICATION_ID")
            .map_err(|_| CmdError::Config("CHANCELA_CMD_APPLICATION_ID is not set".to_string()))?;
        let ama_cert_pem = match std::env::var("CHANCELA_CMD_AMA_CERT_PEM").ok() {
            Some(path) if !path.is_empty() => {
                Some(std::fs::read_to_string(&path).map_err(|e| {
                    CmdError::Config(format!(
                        "failed to read CHANCELA_CMD_AMA_CERT_PEM '{path}': {e}"
                    ))
                })?)
            }
            _ => None,
        };
        Ok(CmdConfig {
            env,
            application_id,
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
}
