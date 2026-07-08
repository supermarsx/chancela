//! [`SignerProvider`] — the abstraction over a signing device or service, and its two real
//! implementations: [`SmartcardProvider`] (Cartão de Cidadão via `chancela-smartcard`) and
//! [`CmdProvider`] (Chave Móvel Digital via `chancela-cmd`).
//!
//! A provider does one cryptographic job: given the SHA-256 of the CAdES *signed attributes*, it
//! returns a [`RawSignature`] over that digest, plus the signing certificate needed to build the
//! attributes in the first place. CMS/CAdES/PAdES assembly and trust decisions live above it in
//! [`crate::pipeline`], [`crate::envelope`], and [`crate::policy`]. This keeps the interactive and
//! platform-specific parts (card PIN dialogs, CMD OTP round-trips) behind a small, mock-testable
//! surface (SIG-01/02).

use chancela_cades::RawSignature;
use chancela_cmd::rand_core::OsRng;
use chancela_cmd::{CertificateChain, ProcessHandle, ScmdClient, ScmdTransport, SignRequest};
use chancela_smartcard::{CryptoToken, TokenCertificate, select_signature_certificate};
use zeroize::Zeroizing;

use crate::{EvidentiaryLevel, SigningError, SigningFamily};

/// A signing device or service able to sign the CAdES signed-attributes digest for one family.
///
/// The trait is object-safe (used as `&dyn SignerProvider` throughout [`crate::envelope`]): all
/// methods take `&self`, are non-generic, and fail with the crate-wide [`SigningError`].
pub trait SignerProvider {
    /// The signing family this provider serves (SIG-01).
    fn family(&self) -> SigningFamily;

    /// The evidentiary level a signature from this provider carries (SIG-01). For the three
    /// certificate-backed families this is [`EvidentiaryLevel::Qualified`]; a provider MUST NOT
    /// report [`EvidentiaryLevel::OtpConfirmation`] here — the OTP is an internal confirmation
    /// step, never the artifact (SIG-02).
    fn evidentiary_level(&self) -> EvidentiaryLevel;

    /// The signer's leaf certificate (DER). Needed *before* signing so the CAdES signed
    /// attributes (signing-certificate-v2, message-digest) can be built and hashed.
    fn signing_certificate_der(&self) -> Result<Vec<u8>, SigningError>;

    /// The immediate issuing-CA certificate (DER), if the provider can present it. Used by the
    /// trusted-list policy gate to resolve the signer's qualified status (SIG-11/23). A smartcard
    /// presents only the leaf (`Ok(None)`); a CMD response carries the chain.
    fn issuer_certificate_der(&self) -> Result<Option<Vec<u8>>, SigningError>;

    /// Sign the SHA-256 of the CAdES signed attributes, returning the raw signature value plus the
    /// signing certificate and chain (the building block for CMS assembly).
    fn sign_signed_attributes(
        &self,
        signed_attrs_digest: &[u8; 32],
    ) -> Result<RawSignature, SigningError>;
}

/// The evidentiary label of the CMD OTP confirmation *step* (SIG-02). Exposed so callers/logs can
/// name it explicitly; it is deliberately **not** what any [`SignerProvider::evidentiary_level`]
/// returns and never labels a produced [`crate::SignatureArtifact`].
pub const OTP_STEP_LEVEL: EvidentiaryLevel = EvidentiaryLevel::OtpConfirmation;

/// A Cartão de Cidadão signer over a `chancela-smartcard` [`CryptoToken`].
///
/// Wraps any token (the real [`chancela_smartcard::Pkcs11Token`] or a
/// [`chancela_smartcard::MockToken`]) and always signs with the qualified **signature**
/// certificate, selected by label — never the authentication certificate (SIG-02).
///
/// The card exposes only the leaf certificate, so the issuing-CA certificate used by the
/// trusted-list policy gate must be supplied out-of-band via [`Self::with_issuer_certificate`]
/// (t41-e4 M2). If none is supplied, [`SignerProvider::issuer_certificate_der`] returns
/// `Ok(None)` and a configured TSL gate will fail with [`SigningError::MissingIssuerCertificate`].
pub struct SmartcardProvider<T: CryptoToken> {
    token: T,
    issuer_certificate_der: Option<Vec<u8>>,
}

impl<T: CryptoToken> SmartcardProvider<T> {
    /// Wrap a token as a Cartão de Cidadão signer, with no out-of-band issuer certificate.
    pub fn new(token: T) -> Self {
        Self {
            token,
            issuer_certificate_der: None,
        }
    }

    /// Supply the issuing-CA certificate (DER) out-of-band (t41-e4 M2).
    ///
    /// The Cartão de Cidadão presents only its leaf certificate; the immediate issuing-CA
    /// certificate is needed by the trusted-list policy gate to resolve the signer's
    /// qualified status (SIG-11/23). Pass the configured CA bundle's relevant issuer DER
    /// here so [`SignerProvider::issuer_certificate_der`] can surface it; `None` clears it.
    pub fn with_issuer_certificate(mut self, issuer_certificate_der: Option<Vec<u8>>) -> Self {
        self.issuer_certificate_der = issuer_certificate_der;
        self
    }

    /// Borrow the underlying token.
    pub fn token(&self) -> &T {
        &self.token
    }

    /// Enumerate the card and select the qualified-signature certificate (by CKA_LABEL).
    fn signature_certificate(&self) -> Result<TokenCertificate, SigningError> {
        let certs = self
            .token
            .list_certificates()
            .map_err(|e| SigningError::Provider(e.to_string()))?;
        select_signature_certificate(&certs)
            .cloned()
            .ok_or_else(|| {
                SigningError::Provider(
                    "no CITIZEN SIGNATURE CERTIFICATE present on the card".to_string(),
                )
            })
    }
}

impl<T: CryptoToken> SignerProvider for SmartcardProvider<T> {
    fn family(&self) -> SigningFamily {
        SigningFamily::CartaoDeCidadao
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        EvidentiaryLevel::Qualified
    }

    fn signing_certificate_der(&self) -> Result<Vec<u8>, SigningError> {
        Ok(self.signature_certificate()?.cert_der)
    }

    fn issuer_certificate_der(&self) -> Result<Option<Vec<u8>>, SigningError> {
        // t41-e4 M2: surface the out-of-band issuer CA if supplied. The card itself exposes
        // only the leaf; without this the TSL trust gate cannot resolve the signer's status.
        Ok(self.issuer_certificate_der.clone())
    }

    fn sign_signed_attributes(
        &self,
        signed_attrs_digest: &[u8; 32],
    ) -> Result<RawSignature, SigningError> {
        let cert = self.signature_certificate()?;
        self.token
            .sign_digest(&cert, signed_attrs_digest)
            .map_err(|e| SigningError::Provider(e.to_string()))
    }
}

/// A Chave Móvel Digital signer over a `chancela-cmd` [`ScmdClient`].
///
/// The SIG-02 flow is inherently two-step (a PIN starts the signature and dispatches an OTP; the
/// citizen then confirms with the OTP). `CmdProvider` bridges that into the single
/// [`SignerProvider::sign_signed_attributes`] call by taking an **OTP source** closure `F` invoked
/// with the pending [`ProcessHandle`] — in tests a fixed OTP, in production a UI callback. The OTP
/// is only ever a confirmation step; the produced artifact is the qualified signature (SIG-02).
pub struct CmdProvider<T: ScmdTransport, F> {
    client: ScmdClient<T>,
    user_id: String,
    /// The CMD signature PIN (knowledge factor). Held as [`Zeroizing<String>`] so the
    /// PIN is overwritten in memory when the provider is dropped (t41-e4 M1).
    pin: Zeroizing<String>,
    doc_name: String,
    otp_source: F,
}

impl<T, F> CmdProvider<T, F>
where
    T: ScmdTransport,
    F: Fn(&ProcessHandle) -> Result<String, SigningError>,
{
    /// Build a CMD provider. `user_id` is the citizen mobile in SCMD format (`+351 XXXXXXXXX`),
    /// `pin` the CMD signature PIN (knowledge factor), `doc_name` a human-readable label shown on
    /// the device, and `otp_source` a callback that yields the OTP (possession factor).
    pub fn new(
        client: ScmdClient<T>,
        user_id: impl Into<String>,
        pin: impl Into<String>,
        doc_name: impl Into<String>,
        otp_source: F,
    ) -> Self {
        Self {
            client,
            user_id: user_id.into(),
            pin: Zeroizing::new(pin.into()),
            doc_name: doc_name.into(),
            otp_source,
        }
    }

    /// Borrow the underlying SCMD client (e.g. to inspect a mock's recorded requests in tests).
    pub fn client(&self) -> &ScmdClient<T> {
        &self.client
    }

    fn certificate_chain(&self) -> Result<CertificateChain, SigningError> {
        self.client
            .get_certificate(&self.user_id)
            .map_err(|e| SigningError::Provider(e.to_string()))
    }
}

impl<T, F> SignerProvider for CmdProvider<T, F>
where
    T: ScmdTransport,
    F: Fn(&ProcessHandle) -> Result<String, SigningError>,
{
    fn family(&self) -> SigningFamily {
        SigningFamily::ChaveMovelDigital
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        // Qualified — the OTP is an internal confirmation step, never surfaced here (SIG-02).
        EvidentiaryLevel::Qualified
    }

    fn signing_certificate_der(&self) -> Result<Vec<u8>, SigningError> {
        Ok(self.certificate_chain()?.leaf_der)
    }

    fn issuer_certificate_der(&self) -> Result<Option<Vec<u8>>, SigningError> {
        Ok(self.certificate_chain()?.chain_der.into_iter().next())
    }

    fn sign_signed_attributes(
        &self,
        signed_attrs_digest: &[u8; 32],
    ) -> Result<RawSignature, SigningError> {
        // `OsRng` is only consumed by the PROD field-encryption hook; cleartext (preprod) ignores
        // it. It is the CSPRNG unified across rsa/p256 via rand_core 0.6 (t4-m1).
        let mut rng = OsRng;
        let handle = self
            .client
            .request_signature(
                &mut rng,
                &SignRequest {
                    user_id: self.user_id.clone(),
                    // `SignRequest::pin` is a plain `String` (its `Drop` zeroizes it);
                    // deref the `Zeroizing` wrapper to copy the PIN out of secure storage.
                    pin: (*self.pin).clone(),
                    doc_name: self.doc_name.clone(),
                    hash: signed_attrs_digest.to_vec(),
                },
            )
            .map_err(|e| SigningError::Provider(e.to_string()))?;
        // Acquire the possession factor (OTP) for this pending process, then confirm.
        let otp = (self.otp_source)(&handle)?;
        self.client
            .confirm_otp(&mut rng, &handle, &otp)
            .map_err(|e| SigningError::Provider(e.to_string()))
    }
}
