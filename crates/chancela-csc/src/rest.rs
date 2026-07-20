//! The CSC v2 JSON wire contract: endpoint paths, the [`Authorization`] header selector, the
//! typed request/response DTOs, and the algorithm OID constants.
//!
//! There is no Rust CSC SDK; this crate implements the CSC v2 REST protocol as a typed
//! `serde_json` client (the direct analogue of `chancela-cmd`'s hand-built SOAP), so a single
//! adapter serves every CSC-compliant QTSP. Only the shape the two-phase signing flow needs is
//! modelled — extra members a given QTSP returns are ignored (`serde` default/skip).
//!
//! References: Cloud Signature Consortium API v2.0 — `oauth2/token`, `credentials/list`,
//! `credentials/info`, `credentials/sendOTP`, `credentials/authorize`, `signatures/signHash`.

use serde::{Deserialize, Serialize};

// --- Endpoint paths (relative to `CscConfig::base_url`) -------------------------------------------

/// OAuth2 token endpoint (RFC 6749; CSC §8).
pub const PATH_OAUTH2_TOKEN: &str = "oauth2/token";
/// `credentials/list` — enumerate the account's signing credentials (CSC §11.4).
pub const PATH_CREDENTIALS_LIST: &str = "credentials/list";
/// `credentials/info` — a credential's certificate chain + key/auth metadata (CSC §11.5).
pub const PATH_CREDENTIALS_INFO: &str = "credentials/info";
/// `credentials/sendOTP` — dispatch the one-time password to the signer (CSC §11.7).
pub const PATH_CREDENTIALS_SEND_OTP: &str = "credentials/sendOTP";
/// `credentials/authorize` — authorize signing of the hash(es), returning the SAD (CSC §11.6).
pub const PATH_CREDENTIALS_AUTHORIZE: &str = "credentials/authorize";
/// `signatures/signHash` — hash-in → signature-out over an authorized SAD (CSC §11.9).
pub const PATH_SIGNATURES_SIGN_HASH: &str = "signatures/signHash";

// --- Algorithm OIDs -------------------------------------------------------------------------------

/// SHA-256 digest algorithm OID.
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// RSASSA-PKCS1-v1_5 with SHA-256 signature algorithm OID.
pub const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
/// `rsaEncryption` key algorithm OID (a credential advertising this uses RSA).
pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// ECDSA with SHA-256 signature algorithm OID.
pub const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
/// `id-ecPublicKey` key algorithm OID (a credential advertising this uses ECDSA).
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

// --- HTTP authorization selector ------------------------------------------------------------------

/// Which HTTP `Authorization` header a CSC request carries.
///
/// The token endpoint authenticates the *client* (HTTP Basic, RFC 6749 §2.3.1); every other CSC
/// call authenticates with the *bearer* access token obtained from it.
#[derive(Clone, Copy)]
pub enum Authorization<'a> {
    /// No `Authorization` header.
    None,
    /// HTTP Basic client authentication (`client_id:client_secret`), for `oauth2/token`.
    Basic {
        /// OAuth2 client id.
        client_id: &'a str,
        /// OAuth2 client secret.
        client_secret: &'a str,
    },
    /// Bearer access-token authentication, for every CSC operation call.
    Bearer(&'a str),
}

// --- oauth2/token ---------------------------------------------------------------------------------

/// `oauth2/token` request (service-level `client_credentials` grant).
#[derive(Debug, Serialize)]
pub struct TokenRequest<'a> {
    /// The OAuth2 grant type (`"client_credentials"` for service authorization).
    pub grant_type: &'a str,
    /// The requested scope (`"service"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<&'a str>,
}

/// `oauth2/token` response.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// The bearer access token used for subsequent CSC calls.
    pub access_token: String,
    /// The token type (`"Bearer"`); informational.
    #[serde(default)]
    pub token_type: Option<String>,
    /// Lifetime in seconds; informational (each phase re-authenticates).
    #[serde(default)]
    pub expires_in: Option<i64>,
}

// --- credentials/list -----------------------------------------------------------------------------

/// `credentials/list` request.
#[derive(Debug, Serialize)]
pub struct CredentialsListRequest<'a> {
    /// An optional user id to scope the listing (user authorization).
    #[serde(rename = "userID", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<&'a str>,
}

/// `credentials/list` response.
#[derive(Debug, Deserialize)]
pub struct CredentialsListResponse {
    /// The account's signing-credential ids.
    #[serde(rename = "credentialIDs", default)]
    pub credential_ids: Vec<String>,
}

// --- credentials/info -----------------------------------------------------------------------------

/// `credentials/info` request.
#[derive(Debug, Serialize)]
pub struct CredentialsInfoRequest<'a> {
    /// The credential to describe.
    #[serde(rename = "credentialID")]
    pub credential_id: &'a str,
    /// `"chain"` → return the leaf + issuer chain; `"single"` → leaf only.
    pub certificates: &'a str,
    /// Whether to include parsed certificate info (subject/issuer/validity).
    #[serde(rename = "certInfo")]
    pub cert_info: bool,
    /// Whether to include the authorization metadata (`authMode`, `PIN`, `OTP`).
    #[serde(rename = "authInfo")]
    pub auth_info: bool,
}

/// `credentials/info` response (only the members the signing flow needs).
#[derive(Debug, Deserialize)]
pub struct CredentialsInfoResponse {
    /// The signing key metadata.
    pub key: KeyInfo,
    /// The certificate material.
    pub cert: CertInfo,
    /// The credential authorization mode (`"explicit"` | `"oauth2code"`).
    #[serde(rename = "authMode", default)]
    pub auth_mode: Option<String>,
    /// The Signature Activation Level (`"1"` | `"2"`).
    #[serde(rename = "SCAL", default)]
    pub scal: Option<String>,
    /// Whether/how a PIN is required to activate the credential.
    #[serde(rename = "PIN", default)]
    pub pin: Option<FactorInfo>,
    /// Whether/how an OTP is delivered to activate the credential.
    #[serde(rename = "OTP", default)]
    pub otp: Option<FactorInfo>,
}

/// A credential's signing-key metadata.
#[derive(Debug, Deserialize)]
pub struct KeyInfo {
    /// The key/signature algorithm OIDs this credential supports.
    #[serde(default)]
    pub algo: Vec<String>,
    /// The key status (`"enabled"` | `"disabled"`).
    #[serde(default)]
    pub status: Option<String>,
}

/// A credential's certificate material.
#[derive(Debug, Deserialize)]
pub struct CertInfo {
    /// The certificate chain, base64-encoded DER, **leaf first** then issuers.
    #[serde(default)]
    pub certificates: Vec<String>,
    /// The certificate status (`"valid"` | `"expired"` | …); informational.
    #[serde(default)]
    pub status: Option<String>,
}

/// A PIN/OTP activation-factor descriptor.
#[derive(Debug, Deserialize)]
pub struct FactorInfo {
    /// `"true"` | `"false"` | `"optional"` — whether this factor is present/required.
    #[serde(default)]
    pub presence: Option<String>,
}

impl FactorInfo {
    /// Whether this factor is present/required (`presence` is `"true"`).
    pub fn is_required(&self) -> bool {
        self.presence.as_deref() == Some("true")
    }
}

// --- credentials/sendOTP --------------------------------------------------------------------------

/// `credentials/sendOTP` request — dispatch the OTP to the signer's device.
#[derive(Debug, Serialize)]
pub struct SendOtpRequest<'a> {
    /// The credential whose OTP should be dispatched.
    #[serde(rename = "credentialID")]
    pub credential_id: &'a str,
}

// --- credentials/authorize ------------------------------------------------------------------------

/// `credentials/authorize` request — authorize signing of `hash`, yielding a SAD.
#[derive(Debug, Serialize)]
pub struct AuthorizeRequest<'a> {
    /// The credential to authorize.
    #[serde(rename = "credentialID")]
    pub credential_id: &'a str,
    /// The number of signatures this authorization covers (always 1 here).
    #[serde(rename = "numSignatures")]
    pub num_signatures: u32,
    /// The base64-encoded hash(es) to be signed.
    pub hash: Vec<String>,
    /// The hash algorithm OID.
    #[serde(rename = "hashAlgorithmOID")]
    pub hash_algorithm_oid: &'a str,
    /// The OTP activation factor (transient; the CSC analogue of CMD's SMS OTP).
    #[serde(rename = "OTP", skip_serializing_if = "Option::is_none")]
    pub otp: Option<&'a str>,
    /// The static credential PIN, when the QTSP requires one (transient).
    #[serde(rename = "PIN", skip_serializing_if = "Option::is_none")]
    pub pin: Option<&'a str>,
    /// A human-readable description shown to the signer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'a str>,
}

/// `credentials/authorize` response.
#[derive(Debug, Deserialize)]
pub struct AuthorizeResponse {
    /// The Signature Activation Data authorizing `signatures/signHash`.
    #[serde(rename = "SAD")]
    pub sad: String,
    /// SAD lifetime in seconds; informational.
    #[serde(rename = "expiresIn", default)]
    pub expires_in: Option<i64>,
}

// --- signatures/signHash --------------------------------------------------------------------------

/// `signatures/signHash` request — sign the authorized hash(es).
#[derive(Debug, Serialize)]
pub struct SignHashRequest<'a> {
    /// The credential to sign with.
    #[serde(rename = "credentialID")]
    pub credential_id: &'a str,
    /// The Signature Activation Data from `credentials/authorize`.
    #[serde(rename = "SAD")]
    pub sad: &'a str,
    /// The base64-encoded hash(es) to sign (must match the authorized hash).
    pub hash: Vec<String>,
    /// The hash algorithm OID.
    #[serde(rename = "hashAlgorithmOID")]
    pub hash_algorithm_oid: &'a str,
    /// The signature algorithm OID.
    #[serde(rename = "signAlgo")]
    pub sign_algo: &'a str,
}

/// `signatures/signHash` response.
#[derive(Debug, Deserialize)]
pub struct SignHashResponse {
    /// The base64-encoded signature value(s), one per input hash.
    #[serde(default)]
    pub signatures: Vec<String>,
}

// --- error body -----------------------------------------------------------------------------------

/// A CSC / OAuth2 error body (`{ "error", "error_description" }`).
#[derive(Debug, Deserialize)]
pub struct ErrorBody {
    /// The machine-readable error code.
    pub error: String,
    /// The human-readable description.
    #[serde(rename = "error_description", default)]
    pub error_description: Option<String>,
}
