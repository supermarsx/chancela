//! The [`RawSignature`] / [`SignatureAlgorithm`] contract consumed across the signing stack.
//!
//! This is the pinned cross-executor contract from `.orchestration/plans/t4.md` §2.2.
//! `chancela-cades` **owns** these types; `chancela-smartcard`, `chancela-cmd`,
//! `chancela-pades`, and `chancela-signing` import them from here so that a token signer
//! (Cartão de Cidadão) and a remote signer (Chave Móvel Digital) emit the *same* shape, and
//! the CMS assembly in [`crate::builder::assemble_cades_b`] consumes it uniformly.

use serde::{Deserialize, Serialize};

/// The signature/digest algorithm profile of a [`RawSignature`].
///
/// The two variants match the two Cartão de Cidadão card generations and the Chave Móvel
/// Digital service (SIG-01):
/// - `RsaPkcs1Sha256` — CC v1 (pre-June 2024, RSA-2048) and CMD (raw PKCS#1 v1.5).
/// - `EcdsaP256Sha256` — CC v2 (June 2024+, NIST P-256).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 over a SHA-256 digest.
    RsaPkcs1Sha256,
    /// ECDSA on NIST P-256 over a SHA-256 digest.
    EcdsaP256Sha256,
}

/// The primitive output of a signing device/service: a signature value over a digest, plus the
/// X.509 material needed to assemble a CMS `SignerInfo`.
///
/// This is **not** itself a CAdES/PAdES artifact — it is the raw building block. A smartcard or
/// remote signer produces a `RawSignature` over the SHA-256 of the signed attributes (see
/// [`crate::builder::signed_attributes_digest`]); [`crate::builder::assemble_cades_b`] then wraps
/// it into a detached CAdES-B `SignedData` (SIG-01/02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RawSignature {
    /// The signature/digest algorithm used to produce [`Self::signature`].
    pub algorithm: SignatureAlgorithm,
    /// The signature value: DER-encoded `ECDSA-Sig-Value` (r, s) for ECDSA, or the raw PKCS#1
    /// v1.5 signature bytes for RSA.
    pub signature: Vec<u8>,
    /// The signer's X.509 certificate, DER-encoded.
    pub signing_cert_der: Vec<u8>,
    /// The issuer chain above the signer, DER-encoded, leaf **excluded** (the leaf is
    /// [`Self::signing_cert_der`]).
    pub chain_der: Vec<Vec<u8>>,
}

impl RawSignature {
    /// Convenience constructor.
    pub fn new(
        algorithm: SignatureAlgorithm,
        signature: Vec<u8>,
        signing_cert_der: Vec<u8>,
        chain_der: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            algorithm,
            signature,
            signing_cert_der,
            chain_der,
        }
    }
}
