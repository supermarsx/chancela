//! The SIG-02 request -> OTP -> retrieve flow, producing a [`RawSignature`].
//!
//! Chave Movel Digital is a *qualified remote signature*. The citizen authorizes with
//! two factors — the **PIN** (knowledge) sent in `CCMovelSign`, and the **OTP**
//! (possession) confirmed in `ValidateOtp` — which together establish sole control
//! (spec 04 SIG-02). The OTP is a confirmation *step inside* the qualified flow; it is
//! **never** the signature. `ValidateOtp` returns a raw RSA-PKCS#1v1.5 signature value
//! over the DigestInfo of the hash we sent; this crate packages it (with the certificate
//! chain from `GetCertificate`) as a [`RawSignature`], and CMS/CAdES assembly happens in
//! `chancela-cades` / `chancela-signing`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use rsa::rand_core::CryptoRngCore;
use x509_cert::Certificate;
use zeroize::{Zeroize, Zeroizing};

use chancela_cades::{RawSignature, SignatureAlgorithm};

use crate::config::CmdConfig;
use crate::error::CmdError;
use crate::field_encryption::FieldEncryptor;
use crate::soap;
use crate::transport::ScmdTransport;

/// SCMD success status code (`CCMovelSign` / `ValidateOtp` `Code`).
///
/// t41-e4 L9: SCMD v1.6 reports success exclusively as `"200"`. An earlier revision also
/// accepted `"0"` ("some deployments report success as 0"); that path was removed because a
/// malformed or hostile response carrying `Code: 0` would otherwise be treated as success.
/// If a real SCMD deployment is ever observed returning `"0"`, re-enable it via an explicit
/// allowlist entry here — do not broaden silently.
const CODE_OK: &str = "200";

fn is_success(code: &str) -> bool {
    code == CODE_OK
}

/// Inputs to [`ScmdClient::request_signature`].
#[derive(Debug, Clone)]
pub struct SignRequest {
    /// Citizen mobile number in the SCMD format `+351 XXXXXXXXX`.
    pub user_id: String,
    /// The citizen's CMD signature PIN (knowledge factor).
    pub pin: String,
    /// A human-readable document name shown to the user on their device.
    pub doc_name: String,
    /// The digest to be signed (raw bytes; base64-encoded on the wire). In the CAdES flow
    /// this is the SHA-256 of the SignedAttributes computed by `chancela-cades`.
    pub hash: Vec<u8>,
}

impl Drop for SignRequest {
    fn drop(&mut self) {
        // t41-e4 M1: zeroize the PIN from heap memory when the request is dropped, so the
        // secret does not linger in freed memory. (`String: Zeroize` overwrites the backing
        // buffer in place.) `Zeroizing<String>` would be ideal but changing the public field
        // type would break the struct-literal API used by tests outside this crate; the
        // security outcome (PIN bytes overwritten on drop) is identical.
        self.pin.zeroize();
    }
}

/// A pending signature process returned by `CCMovelSign`. The OTP has been dispatched to
/// the citizen's device; call [`ScmdClient::confirm_otp`] with this handle.
#[derive(Debug, Clone)]
pub struct ProcessHandle {
    /// The SCMD `ProcessId` correlating the OTP confirmation to this request.
    pub process_id: String,
    /// The citizen mobile number, retained so `confirm_otp` can fetch the certificate.
    pub user_id: String,
    /// The `CCMovelSign` status code (`"200"` on success).
    pub code: String,
    /// The `CCMovelSign` status message.
    pub message: String,
}

/// A citizen certificate plus its issuer chain, as returned by `GetCertificate`.
#[derive(Debug, Clone)]
pub struct CertificateChain {
    /// The signing (leaf) certificate, DER-encoded.
    pub leaf_der: Vec<u8>,
    /// The issuer chain, DER-encoded, leaf excluded (matches the [`RawSignature`] contract).
    pub chain_der: Vec<Vec<u8>>,
}

/// The Chave Movel Digital SCMD client, generic over a [`ScmdTransport`].
///
/// Construct with a real [`crate::transport::HttpScmdTransport`] for preprod/prod, or with
/// [`crate::mock::MockScmdTransport`] for offline tests.
pub struct ScmdClient<T: ScmdTransport> {
    transport: T,
    application_id: String,
    encryptor: FieldEncryptor,
}

impl<T: ScmdTransport> ScmdClient<T> {
    /// A client with cleartext fields (preprod). `application_id` is the opaque AMA string.
    pub fn new(transport: T, application_id: impl Into<String>) -> Self {
        ScmdClient {
            transport,
            application_id: application_id.into(),
            encryptor: FieldEncryptor::Cleartext,
        }
    }

    /// A client with an explicit field encryptor (PROD field encryption).
    pub fn with_encryptor(
        transport: T,
        application_id: impl Into<String>,
        encryptor: FieldEncryptor,
    ) -> Self {
        ScmdClient {
            transport,
            application_id: application_id.into(),
            encryptor,
        }
    }

    /// Build a client from a [`CmdConfig`] (derives the field encryptor from the AMA cert).
    pub fn from_config(transport: T, cfg: &CmdConfig) -> Result<Self, CmdError> {
        Ok(ScmdClient {
            transport,
            application_id: cfg.application_id.clone(),
            encryptor: cfg.field_encryptor()?,
        })
    }

    /// Whether this client encrypts sensitive fields (true only for the AMA-RSA encryptor).
    pub fn is_field_encrypting(&self) -> bool {
        self.encryptor.is_encrypting()
    }

    /// Borrow the underlying transport (e.g. to inspect a mock's recorded requests in tests).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn application_id_b64(&self) -> String {
        STANDARD.encode(self.application_id.as_bytes())
    }

    /// `GetCertificate` — fetch the citizen's signing certificate + issuer chain (PEM on
    /// the wire, returned here as DER). Needed before signing to build the CAdES
    /// signing-certificate attribute.
    pub fn get_certificate(&self, user_id: &str) -> Result<CertificateChain, CmdError> {
        let envelope = soap::get_certificate_envelope(&self.application_id_b64(), user_id);
        let response = self
            .transport
            .call(soap::ACTION_GET_CERTIFICATE, &envelope)?;
        if let Some(fault) = soap::fault_message(&response) {
            return Err(CmdError::SoapFault(fault));
        }
        let pem = soap::require_text(&response, "GetCertificateResult")?;
        parse_cert_chain(&pem)
    }

    /// `CCMovelSign` — start a qualified signature over `req.hash`. Dispatches the OTP to the
    /// citizen's device and returns a [`ProcessHandle`]. The PIN and mobile number are passed
    /// through the field encryptor (`rng` is used only when encrypting).
    pub fn request_signature<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        req: &SignRequest,
    ) -> Result<ProcessHandle, CmdError> {
        let pin_field = self.encryptor.encrypt(rng, &req.pin)?;
        let user_field = self.encryptor.encrypt(rng, &req.user_id)?;
        let hash_b64 = STANDARD.encode(&req.hash);
        let envelope = soap::ccmovel_sign_envelope(
            &self.application_id_b64(),
            &req.doc_name,
            &hash_b64,
            &pin_field,
            &user_field,
        );
        let response = self.transport.call(soap::ACTION_CCMOVEL_SIGN, &envelope)?;
        if let Some(fault) = soap::fault_message(&response) {
            return Err(CmdError::SoapFault(fault));
        }
        let code = soap::require_text(&response, "Code")?;
        let message = soap::find_text(&response, "Message").unwrap_or_default();
        if !is_success(&code) {
            return Err(CmdError::ServiceStatus { code, message });
        }
        let process_id = soap::require_text(&response, "ProcessId")?;
        Ok(ProcessHandle {
            process_id,
            user_id: req.user_id.clone(),
            code,
            message,
        })
    }

    /// `ValidateOtp` — confirm the possession factor and retrieve the raw signature.
    ///
    /// On success this also calls `GetCertificate` to attach the citizen's certificate chain,
    /// yielding a complete [`RawSignature`] (RSA-PKCS#1 v1.5 over SHA-256 DigestInfo) for CMS
    /// assembly downstream. The OTP is a confirmation step, never the artifact (SIG-02).
    pub fn confirm_otp<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        handle: &ProcessHandle,
        otp: &str,
    ) -> Result<RawSignature, CmdError> {
        let otp_field = Zeroizing::new(self.encryptor.encrypt(rng, otp)?);
        let envelope =
            soap::validate_otp_envelope(&self.application_id_b64(), &handle.process_id, &otp_field);
        let response = self.transport.call(soap::ACTION_VALIDATE_OTP, &envelope)?;
        if let Some(fault) = soap::fault_message(&response) {
            return Err(CmdError::SoapFault(fault));
        }
        let code = soap::require_text(&response, "Code")?;
        if !is_success(&code) {
            let message = soap::find_text(&response, "Message").unwrap_or_default();
            return Err(CmdError::OtpRejected { code, message });
        }
        let signature_b64 = soap::require_text(&response, "Signature")?;
        let signature = STANDARD
            .decode(signature_b64.trim())
            .map_err(|e| CmdError::Base64(format!("ValidateOtp Signature: {e}")))?;
        let chain = self.get_certificate(&handle.user_id)?;
        Ok(RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            signature,
            chain.leaf_der,
            chain.chain_der,
        ))
    }
}

/// Parse a PEM certificate bundle (leaf first, then issuers) into a [`CertificateChain`].
fn parse_cert_chain(pem: &str) -> Result<CertificateChain, CmdError> {
    let certs = Certificate::load_pem_chain(pem.as_bytes())
        .map_err(|e| CmdError::Certificate(format!("invalid certificate PEM chain: {e}")))?;
    let mut ders: Vec<Vec<u8>> = certs
        .iter()
        .map(|c| {
            c.to_der()
                .map_err(|e| CmdError::Certificate(format!("cannot DER-encode certificate: {e}")))
        })
        .collect::<Result<_, _>>()?;
    if ders.is_empty() {
        return Err(CmdError::Certificate(
            "GetCertificate returned no certificates".to_string(),
        ));
    }
    let leaf_der = ders.remove(0);
    Ok(CertificateChain {
        leaf_der,
        chain_der: ders,
    })
}
