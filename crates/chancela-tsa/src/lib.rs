//! `chancela-tsa` — RFC 3161 qualified timestamp client (spec 04, SIG-22).
//!
//! Self-contained (no `chancela-cades` dependency): this crate speaks the RFC 3161
//! Time-Stamp Protocol directly on top of the RustCrypto ASN.1 stack.
//!
//! - [`request::TimestampRequest`] builds a `TimeStampReq` over a SHA-256
//!   [`MessageImprint`](x509_tsp::MessageImprint) (nonce + `certReq` + optional policy).
//! - [`transport::TsaTransport`] abstracts the HTTP POST of the DER request;
//!   [`transport::HttpTsaTransport`] is the blocking `reqwest` implementation and
//!   [`mock::MockTsaTransport`] replays a canned `TimeStampResp` for offline tests.
//! - [`verify::verify_response`] parses the `TimeStampResp`, extracts the
//!   `TimeStampToken` (a CMS `SignedData` over `TstInfo`), and verifies its structural
//!   integrity: PKIStatus granted, `eContentType` is `id-ct-TSTInfo`, the message imprint
//!   matches the requested digest, the nonce matches, and the `message-digest`/`content-type`
//!   signed attributes bind to the encapsulated `TstInfo`.
//! - [`client::TsaClient`] ties a transport, a request, and a
//!   [`verify::QualifiedTimestampPolicy`] hook (SIG-22) into a one-call `timestamp()`.
//!
//! # Verification boundary
//!
//! This crate carries no asymmetric-crypto dependency (`rsa`/`p256`/`ecdsa`) by design — see
//! `.orchestration/plans/t4.md` §2.1. It therefore verifies the timestamp token's *structure*
//! and its *binding* to the requested digest (imprint + `message-digest` signed attribute), but
//! it does **not** verify the TSA's asymmetric signature value or validate the TSA certificate
//! chain. That is the job of the trust layer: `chancela-tsl` decides whether the signing TSA is a
//! currently-granted qualified TSA, and the CMS signature-value check belongs to the crypto layer
//! (`chancela-cades`/`chancela-signing`). See `TESTING.md`.

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod mock;
pub mod request;
pub mod transport;
pub mod verify;

pub(crate) mod oid;

pub use client::TsaClient;
pub use error::TsaError;
pub use mock::MockTsaTransport;
pub use request::TimestampRequest;
pub use transport::{DEFAULT_PT_TSA_URL, HttpTsaTransport, TsaTransport};
pub use verify::{QualifiedTimestampPolicy, Timestamp, verify_response};
