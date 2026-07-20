//! [`CscClient`] — the typed CSC v2 REST calls the two-phase signing flow needs.
//!
//! Each method builds a typed request ([`crate::rest`]), posts it through the injected
//! [`CscTransport`], parses a structured CSC error body when present, and returns a typed result.
//! The client is generic over the transport, so the whole flow is exercised offline with
//! [`crate::mock::MockCscTransport`] — no live QTSP in CI.
//!
//! CSC v2 endpoints implemented:
//! 1. [`CscClient::authenticate`] (`oauth2/token`) — service-level `client_credentials`, or a
//!    pre-obtained bearer token for user authorization.
//! 2. [`CscClient::list_credentials`] (`credentials/list`) — enumerate signing credentials.
//! 3. [`CscClient::credential_info`] (`credentials/info`) — the signing certificate chain + key
//!    and authorization metadata.
//! 4. [`CscClient::send_otp`] (`credentials/sendOTP`) — dispatch the OTP (the CSC analogue of
//!    CMD's SMS dispatch).
//! 5. [`CscClient::authorize`] (`credentials/authorize`) — submit the OTP/PIN, obtain the SAD.
//! 6. [`CscClient::sign_hash`] (`signatures/signHash`) — hash-in → signature-out over the SAD.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Decode;
use serde::Serialize;
use x509_cert::Certificate;
use zeroize::Zeroizing;

use chancela_cades::{RawSignature, SignatureAlgorithm};

use crate::config::{CscAuthorization, CscConfig, CscSecrets};
use crate::error::CscError;
use crate::rest::{
    self, Authorization, AuthorizeRequest, AuthorizeResponse, CredentialsInfoRequest,
    CredentialsInfoResponse, CredentialsListRequest, CredentialsListResponse, ErrorBody,
    SendOtpRequest, SignHashRequest, SignHashResponse, TokenRequest, TokenResponse,
};
use crate::transport::CscTransport;

/// A signing credential's resolved certificate chain and signing algorithm.
#[derive(Debug, Clone)]
pub struct CredentialCert {
    /// The signing (leaf) certificate, DER-encoded.
    pub leaf_der: Vec<u8>,
    /// The issuer chain, DER-encoded, **leaf excluded** (matches the [`RawSignature`] contract).
    pub chain_der: Vec<Vec<u8>>,
    /// The signature algorithm this credential signs with (derived from `key.algo`).
    pub algorithm: SignatureAlgorithm,
    /// Whether the credential requires an OTP activation factor (drives `send_otp` at initiate).
    pub otp_required: bool,
    /// Whether the credential requires a static PIN activation factor.
    pub pin_required: bool,
}

/// A CSC v2 REST client, generic over a [`CscTransport`].
///
/// Construct with a real [`crate::transport::HttpCscTransport`] for a QTSP sandbox/prod, or with
/// [`crate::mock::MockCscTransport`] for offline tests.
pub struct CscClient<T: CscTransport> {
    transport: T,
    config: CscConfig,
    secrets: CscSecrets,
}

impl<T: CscTransport> CscClient<T> {
    /// Build a client from a transport, non-secret config, and env-loaded secrets.
    pub fn new(transport: T, config: CscConfig, secrets: CscSecrets) -> Self {
        CscClient {
            transport,
            config,
            secrets,
        }
    }

    /// Borrow the non-secret config.
    pub fn config(&self) -> &CscConfig {
        &self.config
    }

    /// Borrow the underlying transport (e.g. to inspect a mock's recorded requests in tests).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Serialize a request DTO to JSON, mapping serialization failure to a config error.
    fn to_json<S: Serialize>(value: &S) -> Result<String, CscError> {
        serde_json::to_string(value)
            .map_err(|e| CscError::Config(format!("failed to build request JSON: {e}")))
    }

    /// Parse a JSON response, first checking for a structured CSC error body.
    fn parse_response<D: serde::de::DeserializeOwned>(body: &str) -> Result<D, CscError> {
        // A CSC error is `{ "error", "error_description" }`; detect it before the happy-path parse
        // so a non-2xx-with-body surfaces the structured service error.
        if let Ok(err) = serde_json::from_str::<ErrorBody>(body) {
            return Err(CscError::Service {
                error: err.error,
                description: err.error_description.unwrap_or_default(),
            });
        }
        serde_json::from_str::<D>(body).map_err(|e| CscError::ResponseParse(format!("{e}")))
    }

    /// **CSC §8 — `oauth2/token`.** Obtain a bearer access token.
    ///
    /// - Service authorization: `client_credentials` grant with HTTP Basic client authentication.
    /// - User authorization: returns the pre-obtained [`CscSecrets::access_token`] (the signer
    ///   authenticated to the QTSP out-of-band); no token call is made.
    ///
    /// The returned token is held in [`Zeroizing`] so it is wiped from memory on drop.
    pub fn authenticate(&self) -> Result<Zeroizing<String>, CscError> {
        if self.config.authorization == CscAuthorization::User {
            return self.secrets.access_token.clone().ok_or_else(|| {
                CscError::Config(
                    "user authorization requires a pre-obtained access token".to_string(),
                )
            });
        }
        let body = Self::to_json(&TokenRequest {
            grant_type: "client_credentials",
            scope: Some(&self.config.scope),
        })?;
        let resp = self.transport.post_json(
            rest::PATH_OAUTH2_TOKEN,
            Authorization::Basic {
                client_id: &self.secrets.client_id,
                client_secret: &self.secrets.client_secret,
            },
            &body,
        )?;
        let token: TokenResponse = Self::parse_response(&resp)?;
        Ok(Zeroizing::new(token.access_token))
    }

    /// **CSC §11.4 — `credentials/list`.** Enumerate the account's signing-credential ids.
    pub fn list_credentials(&self, token: &str) -> Result<Vec<String>, CscError> {
        let body = Self::to_json(&CredentialsListRequest { user_id: None })?;
        let resp = self.transport.post_json(
            rest::PATH_CREDENTIALS_LIST,
            Authorization::Bearer(token),
            &body,
        )?;
        let list: CredentialsListResponse = Self::parse_response(&resp)?;
        Ok(list.credential_ids)
    }

    /// Resolve the signing credential id: the configured one, or the sole credential from
    /// `credentials/list`. Errors if none exist or the choice is ambiguous.
    pub fn resolve_credential_id(&self, token: &str) -> Result<String, CscError> {
        if let Some(id) = &self.config.credential_id {
            return Ok(id.clone());
        }
        let ids = self.list_credentials(token)?;
        match ids.len() {
            0 => Err(CscError::NoCredential {
                provider_id: self.config.provider_id.clone(),
            }),
            1 => Ok(ids.into_iter().next().unwrap()),
            _ => Err(CscError::Config(format!(
                "provider '{}' exposes {} credentials; set credential_id to disambiguate",
                self.config.provider_id,
                ids.len()
            ))),
        }
    }

    /// **CSC §11.5 — `credentials/info`.** Fetch the credential's certificate chain (DER),
    /// signature algorithm, and activation-factor requirements.
    pub fn credential_info(
        &self,
        token: &str,
        credential_id: &str,
    ) -> Result<CredentialCert, CscError> {
        let body = Self::to_json(&CredentialsInfoRequest {
            credential_id,
            certificates: "chain",
            cert_info: true,
            auth_info: true,
        })?;
        let resp = self.transport.post_json(
            rest::PATH_CREDENTIALS_INFO,
            Authorization::Bearer(token),
            &body,
        )?;
        let info: CredentialsInfoResponse = Self::parse_response(&resp)?;
        decode_credential_cert(&info)
    }

    /// **CSC §11.7 — `credentials/sendOTP`.** Dispatch the OTP to the signer's device.
    ///
    /// This is the CSC analogue of `CCMovelSign` dispatching the CMD SMS: it is the out-of-band
    /// activation step invoked at initiate. Called only when the credential requires an OTP.
    pub fn send_otp(&self, token: &str, credential_id: &str) -> Result<(), CscError> {
        let body = Self::to_json(&SendOtpRequest { credential_id })?;
        let resp = self.transport.post_json(
            rest::PATH_CREDENTIALS_SEND_OTP,
            Authorization::Bearer(token),
            &body,
        )?;
        // A success body is empty or `{}`; only a structured error must fail here.
        if let Ok(err) = serde_json::from_str::<ErrorBody>(&resp) {
            return Err(CscError::Service {
                error: err.error,
                description: err.error_description.unwrap_or_default(),
            });
        }
        Ok(())
    }

    /// **CSC §11.6 — `credentials/authorize`.** Authorize signing of `hash`, returning the SAD.
    ///
    /// `otp` / `pin` are transient activation factors submitted here and never retained. The
    /// returned SAD is held in [`Zeroizing`].
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        token: &str,
        credential_id: &str,
        hash: &[u8],
        otp: Option<&str>,
        pin: Option<&str>,
    ) -> Result<Zeroizing<String>, CscError> {
        let hash_b64 = STANDARD.encode(hash);
        let body = Self::to_json(&AuthorizeRequest {
            credential_id,
            num_signatures: 1,
            hash: vec![hash_b64],
            hash_algorithm_oid: rest::OID_SHA256,
            otp,
            pin,
            description: Some("Assinatura de ata"),
        })?;
        let resp = self.transport.post_json(
            rest::PATH_CREDENTIALS_AUTHORIZE,
            Authorization::Bearer(token),
            &body,
        )?;
        let auth: AuthorizeResponse = Self::parse_response(&resp)?;
        Ok(Zeroizing::new(auth.sad))
    }

    /// **CSC §11.9 — `signatures/signHash`.** Sign `hash` under the authorized `sad`, returning
    /// the raw signature value wrapped with the credential's certificate chain as a
    /// [`RawSignature`] (ready for CAdES/CMS assembly).
    pub fn sign_hash(
        &self,
        token: &str,
        credential_id: &str,
        sad: &str,
        hash: &[u8],
        cert: &CredentialCert,
    ) -> Result<RawSignature, CscError> {
        let sign_algo = match cert.algorithm {
            SignatureAlgorithm::RsaPkcs1Sha256 => rest::OID_RSA_SHA256,
            SignatureAlgorithm::EcdsaP256Sha256 => rest::OID_ECDSA_SHA256,
            _ => rest::OID_RSA_SHA256,
        };
        let hash_b64 = STANDARD.encode(hash);
        let body = Self::to_json(&SignHashRequest {
            credential_id,
            sad,
            hash: vec![hash_b64],
            hash_algorithm_oid: rest::OID_SHA256,
            sign_algo,
        })?;
        let resp = self.transport.post_json(
            rest::PATH_SIGNATURES_SIGN_HASH,
            Authorization::Bearer(token),
            &body,
        )?;
        let signed: SignHashResponse = Self::parse_response(&resp)?;
        let sig_b64 = signed.signatures.first().ok_or(CscError::NoSignature)?;
        let signature = STANDARD
            .decode(sig_b64.trim())
            .map_err(|e| CscError::Base64(format!("signHash signature: {e}")))?;
        Ok(RawSignature::new(
            cert.algorithm,
            signature,
            cert.leaf_der.clone(),
            cert.chain_der.clone(),
        ))
    }
}

/// Decode the base64-DER certificate chain and derive the signing algorithm from a
/// `credentials/info` response.
fn decode_credential_cert(info: &CredentialsInfoResponse) -> Result<CredentialCert, CscError> {
    if info.cert.certificates.is_empty() {
        return Err(CscError::Certificate(
            "credentials/info returned no certificates".to_string(),
        ));
    }
    let mut ders: Vec<Vec<u8>> = info
        .cert
        .certificates
        .iter()
        .map(|b64| {
            let der = STANDARD
                .decode(b64.trim())
                .map_err(|e| CscError::Base64(format!("certificate: {e}")))?;
            // Reject anything that is not well-formed X.509 DER, fast, before it reaches CMS.
            Certificate::from_der(&der)
                .map_err(|e| CscError::Certificate(format!("invalid certificate DER: {e}")))?;
            Ok::<Vec<u8>, CscError>(der)
        })
        .collect::<Result<_, _>>()?;
    let leaf_der = ders.remove(0);
    let algorithm = algorithm_from_oids(&info.key.algo);
    Ok(CredentialCert {
        leaf_der,
        chain_der: ders,
        algorithm,
        otp_required: info.otp.as_ref().is_some_and(|f| f.is_required()),
        pin_required: info.pin.as_ref().is_some_and(|f| f.is_required()),
    })
}

/// Pick the signature algorithm from the credential's advertised `key.algo` OIDs. Defaults to
/// RSA when no ECDSA OID is advertised.
fn algorithm_from_oids(algo: &[String]) -> SignatureAlgorithm {
    let is_ecdsa = algo
        .iter()
        .any(|o| o == rest::OID_ECDSA_SHA256 || o == rest::OID_EC_PUBLIC_KEY);
    if is_ecdsa {
        SignatureAlgorithm::EcdsaP256Sha256
    } else {
        SignatureAlgorithm::RsaPkcs1Sha256
    }
}
