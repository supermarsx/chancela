//! `chancela-cmd` — Chave Movel Digital qualified remote-signature SOAP client (spec 04).
//!
//! Hand-builds SOAP 1.1 envelopes for the AMA SCMD service (`CCMovelDigitalSignature.svc`)
//! behind a [`ScmdTransport`] trait, and drives the SIG-02 qualified-signature flow:
//!
//! 1. [`ScmdClient::get_certificate`] (`GetCertificate`) — fetch the citizen's signing cert.
//! 2. [`ScmdClient::request_signature`] (`CCMovelSign`) — start the signature; the PIN is the
//!    knowledge factor and the service dispatches an **OTP** to the citizen's device.
//! 3. [`ScmdClient::confirm_otp`] (`ValidateOtp`) — the citizen supplies the OTP (possession
//!    factor); the service returns a **raw RSA-PKCS#1 v1.5 signature** over the DigestInfo of
//!    the hash we sent.
//!
//! The two factors (PIN + OTP) together establish sole control (SIG-02). The **OTP is a
//! confirmation step inside the qualified flow — never the signature artifact.** This crate
//! produces a [`RawSignature`]; CMS/CAdES assembly (placing the returned bytes as the
//! `signatureValue` with the certificate chain) is done by `chancela-cades` /
//! `chancela-signing`.
//!
//! All default tests are offline via [`MockScmdTransport`]. Real preprod/prod calls are behind
//! the `network-tests` feature + `#[ignore]` (see `TESTING.md`).

pub mod config;
pub mod error;
pub mod field_encryption;
pub mod flow;
pub mod mock;
pub mod soap;
pub mod transport;

pub use config::{CmdConfig, CmdEnv, PREPROD_ENDPOINT, PROD_ENDPOINT};
pub use error::CmdError;
pub use field_encryption::FieldEncryptor;
pub use flow::{CertificateChain, ProcessHandle, ScmdClient, SignRequest};
pub use mock::MockScmdTransport;
pub use transport::{HttpScmdTransport, ScmdTransport};

/// Re-export of the [`RawSignature`] / `SignatureAlgorithm` contract this crate produces
/// (owned by `chancela-cades`, per `.orchestration/plans/t4.md` §2.2).
pub use chancela_cades::{RawSignature, SignatureAlgorithm};

/// Re-export of the RNG trait callers must supply for the PROD field-encryption hook.
/// (This crate does not pull a `getrandom`-enabled RNG; the caller provides one.)
pub use rsa::rand_core;
