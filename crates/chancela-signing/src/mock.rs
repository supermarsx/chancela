//! [`MockProvider`] — an offline [`SignerProvider`] for tests and downstream smoke checks.
//!
//! The signature value is produced by a caller-supplied closure, so the same type serves two
//! purposes:
//! - **Plumbing/labelling tests** ([`MockProvider::deterministic_rsa`]) use a checked-in *public*
//!   certificate and shape-only signature bytes — enough to exercise envelope ordering, the policy
//!   gate, and evidentiary labelling, since `assemble_cades_b` only *parses* the certificate.
//! - **Cryptographic round-trips** ([`MockProvider::new`]) take a real in-test key's signing
//!   closure + certificate, producing signatures that `validate_cades_b` / `validate_pdf_signature`
//!   accept (see `tests/roundtrip.rs`).
//!
//! No private keys are checked in (plan §6): the only fixture is a self-signed *public* cert.

use chancela_cades::{RawSignature, SignatureAlgorithm};

use crate::provider::SignerProvider;
use crate::{EvidentiaryLevel, SigningError, SigningFamily};

/// A self-signed RSA-2048 **public** certificate (DER) for shape-only mock signing.
const FIXTURE_RSA_CERT: &[u8] = include_bytes!("../fixtures/mock_signer_rsa.der");

type SignFn = Box<dyn Fn(&[u8; 32]) -> Result<Vec<u8>, SigningError> + Send + Sync>;

/// An in-memory [`SignerProvider`] whose signature value comes from a closure.
pub struct MockProvider {
    family: SigningFamily,
    evidentiary_level: EvidentiaryLevel,
    algorithm: SignatureAlgorithm,
    cert_der: Vec<u8>,
    chain_der: Vec<Vec<u8>>,
    issuer_cert_der: Option<Vec<u8>>,
    sign: SignFn,
    fail: Option<String>,
}

impl MockProvider {
    /// Build a provider from an explicit certificate and signing closure. The `sign` closure
    /// receives the signed-attributes digest and returns the raw signature value (DER `ECDSA-Sig-
    /// Value` for ECDSA, PKCS#1 v1.5 bytes for RSA). The issuer defaults to the certificate itself
    /// (a self-signed cert is its own issuer); override with [`Self::with_issuer`].
    pub fn new<F>(
        family: SigningFamily,
        evidentiary_level: EvidentiaryLevel,
        algorithm: SignatureAlgorithm,
        cert_der: Vec<u8>,
        sign: F,
    ) -> Self
    where
        F: Fn(&[u8; 32]) -> Result<Vec<u8>, SigningError> + Send + Sync + 'static,
    {
        Self {
            family,
            evidentiary_level,
            algorithm,
            issuer_cert_der: Some(cert_der.clone()),
            cert_der,
            chain_der: Vec::new(),
            sign: Box::new(sign),
            fail: None,
        }
    }

    /// A shape-only provider for `family` using the bundled public RSA certificate. Signatures are
    /// deterministic per digest but **not** cryptographically valid — for plumbing/labelling tests.
    pub fn deterministic_rsa(family: SigningFamily) -> Self {
        Self::new(
            family,
            EvidentiaryLevel::Qualified,
            SignatureAlgorithm::RsaPkcs1Sha256,
            FIXTURE_RSA_CERT.to_vec(),
            |digest| Ok(shape_bytes(digest, 256)),
        )
    }

    /// Set the issuer chain above the leaf (DER, leaf excluded) recorded in the [`RawSignature`].
    pub fn with_chain(mut self, chain_der: Vec<Vec<u8>>) -> Self {
        self.chain_der = chain_der;
        self
    }

    /// Set the issuer certificate the policy gate resolves against (`None` = not presented, like a
    /// smartcard).
    pub fn with_issuer(mut self, issuer_cert_der: Option<Vec<u8>>) -> Self {
        self.issuer_cert_der = issuer_cert_der;
        self
    }

    /// Make every operation fail with `message`, simulating a device/service error.
    pub fn failing(mut self, message: impl Into<String>) -> Self {
        self.fail = Some(message.into());
        self
    }
}

impl SignerProvider for MockProvider {
    fn family(&self) -> SigningFamily {
        self.family
    }

    fn evidentiary_level(&self) -> EvidentiaryLevel {
        self.evidentiary_level
    }

    fn signing_certificate_der(&self) -> Result<Vec<u8>, SigningError> {
        if let Some(message) = &self.fail {
            return Err(SigningError::Provider(message.clone()));
        }
        Ok(self.cert_der.clone())
    }

    fn issuer_certificate_der(&self) -> Result<Option<Vec<u8>>, SigningError> {
        if let Some(message) = &self.fail {
            return Err(SigningError::Provider(message.clone()));
        }
        Ok(self.issuer_cert_der.clone())
    }

    fn sign_signed_attributes(
        &self,
        signed_attrs_digest: &[u8; 32],
    ) -> Result<RawSignature, SigningError> {
        if let Some(message) = &self.fail {
            return Err(SigningError::Provider(message.clone()));
        }
        let signature = (self.sign)(signed_attrs_digest)?;
        Ok(RawSignature::new(
            self.algorithm,
            signature,
            self.cert_der.clone(),
            self.chain_der.clone(),
        ))
    }
}

/// Expand a digest into `n` deterministic (but cryptographically meaningless) bytes.
fn shape_bytes(digest: &[u8; 32], n: usize) -> Vec<u8> {
    (0..n).map(|i| digest[i % 32] ^ (i as u8)).collect()
}
