//! `chancela-scap` — client for AMA's **SCAP** (Sistema de Certificação de Atributos
//! Profissionais) (spec 04; t67 §1.2).
//!
//! SCAP lets a citizen sign *in a professional capacity*: an attribute provider certifies that the
//! signer holds a given professional attribute (e.g. lawyer, notary), which is then bound into the
//! signature. This crate lists attribute providers, fetches the signing citizen's attributes, and
//! produces + verifies a professional-attribute-qualified signature over the xades/cades seam.
//!
//! ## Transport & honesty
//!
//! A [`transport::MockScapTransport`] backed by fixtures is the **default and the only thing tests
//! exercise**; the real preprod/prod `HttpScapTransport` (blocking `reqwest`) is behind config +
//! credentials supplied later. Per `.orchestration/plans/t67.md` §1.2 the evidence markers must
//! *evolve honestly*: a `verified_by_scap` status is emitted **only on a real Granted verification**
//! — never from the mock, which stays `declared_capacity_evidence_only`.
//!
//! ## Layout
//!
//! - [`config`] — `AmaScapConfig` (environment, base URL, credentials, provider filter).
//! - [`transport`] — the `ScapTransport` trait + HTTP and mock implementations.
//! - [`model`] — `AttributeProvider`, `ProfessionalAttribute`, `ScapSignatureEvidence`.
//! - [`client`] — `ScapClient`: provider listing, attribute fetch, qualified sign + verify.
//! - [`error`] — the crate error type.
//!
//! **Status:** skeleton (t67-e0). The module bodies are filled by t67-e4.

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod error;
pub mod model;
pub mod transport;

pub use error::ScapError;
