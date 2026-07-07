//! `chancela-cades` — CMS SignedData / CAdES-B build + validate primitives (spec 04).
//!
//! This crate is the crypto foundation of the signature subsystem. It owns the
//! [`RawSignature`] / [`SignatureAlgorithm`] contract (see `.orchestration/plans/t4.md` §2.2)
//! that `chancela-smartcard`, `chancela-cmd`, `chancela-pades`, and `chancela-signing` code
//! against, plus the detached CAdES-B build/validate functions.
//!
//! It does **crypto, not trust decisions** — qualified-status resolution and trust-chain building
//! are the caller's job via `chancela-tsl`. A successful [`validate_cades_b`] means the signature
//! is cryptographically valid over a content digest and carries well-formed CAdES-B attributes.
//!
//! ## Flow
//!
//! 1. Hash the detached content with SHA-256 → `content_digest`.
//! 2. [`signed_attributes_digest`] builds the CAdES-B signed attributes (content-type,
//!    message-digest, signing-time, signing-certificate-v2) and returns the SHA-256 to sign.
//! 3. A token/remote signer signs that digest, producing a [`RawSignature`].
//! 4. [`assemble_cades_b`] wraps it into a detached CAdES-B `SignedData` (DER `ContentInfo`).
//! 5. [`validate_cades_b`] structurally and cryptographically verifies such a message.
//!
//! ## Supported profiles (SIG-01)
//!
//! - `RsaPkcs1Sha256` — RSASSA-PKCS1-v1_5 / SHA-256 (Cartão de Cidadão v1, Chave Móvel Digital).
//! - `EcdsaP256Sha256` — ECDSA P-256 / SHA-256 (Cartão de Cidadão v2).

mod attrs;
mod oids;

#[cfg(test)]
mod tests;

pub mod builder;
pub mod error;
pub mod raw_signature;
pub mod validate;

pub use builder::{assemble_cades_b, signed_attributes_digest};
pub use error::CadesError;
pub use raw_signature::{RawSignature, SignatureAlgorithm};
pub use validate::{CadesValidation, validate_cades_b};
