//! `chancela-smartcard` — Cartão de Cidadão signing via PC/SC + PKCS#11 (spec 04).
//!
//! Qualified electronic signatures with the Portuguese citizen card, driven
//! through the Autenticação.gov middleware. The design is **trait-first** so all
//! logic above the PKCS#11 boundary is unit-tested offline (plan §3):
//!
//! - [`CryptoToken`] is the signing boundary; [`Pkcs11Token`] is the real
//!   `cryptoki`-backed implementation and [`MockToken`] the in-memory stand-in
//!   that drives CI tests with no reader.
//! - The signer **branches on card generation** — CC v1 uses RSA-2048 via
//!   `CKM_RSA_PKCS` over a `DigestInfo`, CC v2 (June 2024+) uses P-256 via
//!   `CKM_ECDSA` re-encoded to DER (plan §1.2, risk #3).
//! - Login defaults to a **NULL PIN** (protected authentication path): the
//!   middleware owns the PIN/CAN dialog. An **optional in-app PIN** may instead be
//!   presented to `C_Login` ([`CryptoToken::sign_digest_with_pin`], t67) for
//!   co-located deployments where the citizen enters the PIN in the app rather than
//!   at the reader. This is an honest, deliberate weakening of the prior
//!   "no credential ever enters the process" guarantee: the PIN is carried only as
//!   a borrowed view of a caller-owned `zeroize::Zeroizing` buffer, handed
//!   straight to a self-zeroizing PKCS#11 secret, and never logged, `Debug`-printed,
//!   persisted, or placed in an error message (plan §6). `None` preserves the
//!   original NULL-PIN path exactly.
//! - Reader detection ([`detect`]) never panics: zero readers is a clean empty
//!   result, an absent PC/SC service is a typed error.
//!
//! Signing produces a [`chancela_cades::RawSignature`] — the CMS/CAdES assembly
//! happens in `chancela-cades` / `chancela-signing`, not here (plan §2.2).
//!
//! The PKCS#11 module path defaults per-OS and is overridable via
//! `CHANCELA_PTEID_PKCS11_MODULE` (plan §2.3). Real-card and reader-enumeration
//! tests are `#[ignore]` + `hardware-tests`-gated; see `TESTING.md`.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod mock;
pub mod pkcs11;
pub mod reader;
pub mod token;

pub use error::{PinTriesLeft, SmartcardError};
pub use mock::MockToken;
pub use pkcs11::{Pkcs11Token, resolve_module_path};
pub use reader::{CardReaders, PcscReaders, ReaderInfo, detect};
pub use token::{
    CertUsage, CryptoToken, TokenCertificate, select_authentication_certificate,
    select_signature_certificate,
};

// Re-export the shared signature contract so downstream crates can name it
// through this crate too (it is owned by `chancela-cades`, plan §2.2).
pub use chancela_cades::{RawSignature, SignatureAlgorithm};
