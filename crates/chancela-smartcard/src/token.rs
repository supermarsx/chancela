//! The [`CryptoToken`] trait + [`TokenCertificate`] — the mock-testable PKCS#11
//! boundary. Everything above this boundary (cert selection, algorithm
//! branching) is exercised offline via [`crate::mock::MockToken`].

use chancela_cades::{RawSignature, SignatureAlgorithm};

use crate::error::SmartcardError;

/// CKA_LABEL of the qualified-signature certificate on a Cartão de Cidadão.
pub const LABEL_SIGNATURE_CERT: &str = "CITIZEN SIGNATURE CERTIFICATE";
/// CKA_LABEL of the authentication certificate on a Cartão de Cidadão.
pub const LABEL_AUTH_CERT: &str = "CITIZEN AUTHENTICATION CERTIFICATE";
/// CKA_LABEL of the qualified-signature private key.
pub const LABEL_SIGNATURE_KEY: &str = "CITIZEN SIGNATURE KEY";
/// CKA_LABEL of the authentication private key.
pub const LABEL_AUTH_KEY: &str = "CITIZEN AUTHENTICATION KEY";

/// What a certificate on the card is for. Selection is by CKA_LABEL, **never**
/// by slot index (plan §1.2): a card may reorder objects but the labels are
/// fixed by the Autenticação.gov middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertUsage {
    /// Qualified electronic signature (`CITIZEN SIGNATURE ...`). This is the key
    /// used for legally-qualified signing and requires the citizen to have
    /// activated it; it is `CKA_ALWAYS_AUTHENTICATE` (PIN per operation).
    QualifiedSignature,
    /// Authentication only (`CITIZEN AUTHENTICATION ...`) — NOT a qualified
    /// signature. Surfacing this as a signature would be a compliance error.
    Authentication,
    /// Any other certificate object present on the card.
    Other,
}

impl CertUsage {
    /// Classify a certificate by its CKA_LABEL.
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        let upper = label.to_ascii_uppercase();
        if upper.contains("SIGNATURE") {
            CertUsage::QualifiedSignature
        } else if upper.contains("AUTHENTICATION") {
            CertUsage::Authentication
        } else {
            CertUsage::Other
        }
    }
}

/// A certificate object read from the token.
///
/// Carries the DER cert plus its detected [`SignatureAlgorithm`] (RSA for CC v1,
/// P-256 ECDSA for CC v2 — plan §1.2) so callers can branch without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenCertificate {
    /// The PKCS#11 CKA_LABEL, e.g. `"CITIZEN SIGNATURE CERTIFICATE"`.
    pub label: String,
    /// The X.509 certificate, DER-encoded.
    pub cert_der: Vec<u8>,
    /// The signing algorithm implied by the certificate's public key.
    pub algorithm: SignatureAlgorithm,
}

impl TokenCertificate {
    /// The usage this certificate is intended for, from its label.
    #[must_use]
    pub fn usage(&self) -> CertUsage {
        CertUsage::from_label(&self.label)
    }
}

/// The mock-testable boundary over a PKCS#11 token (Cartão de Cidadão).
///
/// The real [`crate::pkcs11::Pkcs11Token`] talks to the Autenticação.gov
/// middleware; [`crate::mock::MockToken`] is an in-memory stand-in so all logic
/// above this trait runs in CI with no reader (plan §3).
pub trait CryptoToken {
    /// Enumerate the certificate objects on the token.
    ///
    /// # Errors
    /// [`SmartcardError`] if the token cannot be read (no card, PKCS#11 error).
    fn list_certificates(&self) -> Result<Vec<TokenCertificate>, SmartcardError>;

    /// Sign a 32-byte SHA-256 digest with the key backing `cert`.
    ///
    /// The implementation logs in with a **NULL PIN** (protected authentication
    /// path — the middleware owns the PIN dialog, plan §1.2) and branches on
    /// `cert.algorithm`: `CKM_RSA_PKCS` over a `DigestInfo` for RSA, `CKM_ECDSA`
    /// over the bare digest for P-256 (re-encoded to DER for CMS).
    ///
    /// # Errors
    /// [`SmartcardError`] if no matching key is found, login/sign fails, or the
    /// returned value is malformed.
    fn sign_digest(
        &self,
        cert: &TokenCertificate,
        digest: &[u8; 32],
    ) -> Result<RawSignature, SmartcardError>;
}

/// Select the qualified-signature certificate from an enumerated list, by label.
///
/// This is the certificate a qualified signature MUST use — the authentication
/// certificate is deliberately excluded (plan §1.2 / SIG-02).
#[must_use]
pub fn select_signature_certificate(certs: &[TokenCertificate]) -> Option<&TokenCertificate> {
    certs
        .iter()
        .find(|c| c.usage() == CertUsage::QualifiedSignature)
}

/// Select the authentication certificate from an enumerated list, by label.
#[must_use]
pub fn select_authentication_certificate(certs: &[TokenCertificate]) -> Option<&TokenCertificate> {
    certs
        .iter()
        .find(|c| c.usage() == CertUsage::Authentication)
}
