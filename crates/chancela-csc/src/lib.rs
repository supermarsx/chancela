//! `chancela-csc` — a generic Cloud Signature Consortium (CSC) API v2 remote-signature REST
//! client (spec 04; t59 Slice 2).
//!
//! There is **no Rust SDK** for the Portuguese/EU remote QTSPs (Multicert, DigitalSign, …); the
//! interoperable standard is the **CSC API** (now v2.x, OAuth2 + hash-in → signature-out against a
//! cloud QSCD). This crate implements that protocol as a typed `serde_json` REST client behind a
//! [`CscTransport`] trait — the direct analogue of how `chancela-cmd` implements AMA's SOAP — so
//! **one adapter serves every CSC-compliant QTSP**, selected by config. No vendor SDK, no vendor
//! binary.
//!
//! ## The CSC v2 flow (what the two-phase signing needs)
//!
//! 1. [`CscClient::authenticate`] (`oauth2/token`) — OAuth2 service (`client_credentials`) or a
//!    pre-obtained user access token.
//! 2. [`CscClient::list_credentials`] / [`CscClient::credential_info`] — find the signing
//!    credential and its certificate chain (+ key/OTP metadata).
//! 3. [`CscClient::send_otp`] (`credentials/sendOTP`) — dispatch the OTP/SAD activation.
//! 4. [`CscClient::authorize`] (`credentials/authorize`) — submit the OTP → Signature Activation
//!    Data.
//! 5. [`CscClient::sign_hash`] (`signatures/signHash`) — hash-in → raw signature-out.
//!
//! ## The frozen seam
//!
//! [`CscRemoteSource`] implements the frozen
//! [`chancela_signing::RemoteSigningSource`](chancela_signing::RemoteSigningSource) trait
//! (`initiate` → `confirm`), mirroring
//! [`CmdRemoteSource`](chancela_signing::CmdRemoteSource) semantics exactly, so an api layer holds
//! `Box<dyn RemoteSigningSource>` and drives CMD + every CSC QTSP uniformly. The resumable session
//! it returns is **secret-free** (no PIN/OTP/SAD/token); the trusted-list gate is fail-closed
//! (SIG-11/23); the produced artifact is a genuine qualified CAdES-B CMS ready for
//! `chancela_pades::embed_signature` (SIG-01/02).
//!
//! All default tests are offline via [`MockCscTransport`]. Real per-provider signing is blocked on
//! each QTSP's own onboarding/credentials (the CSC analogue of CMD's AMA blocker) and is an ops
//! step; live calls are behind the `network-tests` feature + `#[ignore]`.

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod error;
pub mod mock;
pub mod rest;
pub mod source;
pub mod transport;

pub use client::{CredentialCert, CscClient};
pub use config::{CscAuthorization, CscConfig, CscProviderInfo, CscSecrets, DEFAULT_SCOPE};
pub use error::CscError;
pub use mock::MockCscTransport;
pub use source::CscRemoteSource;
pub use transport::{CscTransport, HttpCscTransport};

/// Re-export of the [`RawSignature`] / `SignatureAlgorithm` contract this crate produces
/// (owned by `chancela-cades`; consumed by `chancela-signing`'s CMS assembly).
pub use chancela_cades::{RawSignature, SignatureAlgorithm};

/// Re-export of the frozen [`RemoteSigningSource`](chancela_signing::RemoteSigningSource) seam this
/// crate implements, so downstream (the api registry) can name it through this crate.
pub use chancela_signing::{RemoteInitiate, RemoteSignSession, RemoteSigningSource};
