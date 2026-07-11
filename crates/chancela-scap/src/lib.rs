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
//! ## The XAdES hook
//!
//! A professional-attribute signature binds the attribute into the signature. The CAdES form is
//! implemented here over the `chancela-cades` public API; the XAdES form lives in `chancela-xades`,
//! whose surface is built concurrently (t67-e2) and not yet stable. This crate therefore does
//! **not** depend on `chancela-xades`: the binding is abstracted behind the in-crate
//! [`binder::AttributeSignatureBinder`] trait, so a XAdES-backed binder can be supplied later (by
//! the API layer, t67-e10) without editing this crate.
//!
//! ## Layout
//!
//! - [`config`] — `AmaScapConfig` (environment, base URL, credentials, provider filter).
//! - [`transport`] — the `ScapTransport` trait + HTTP and mock implementations, and the
//!   compile-time honesty enforcement (mock cannot mint a verified status).
//! - [`model`] — `AttributeProvider`, `ProfessionalAttribute`, `ScapSignatureEvidence`.
//! - [`binder`] — the `AttributeSignatureBinder` trait (XAdES hook) + the CAdES default binder.
//! - [`client`] — `ScapClient`: provider listing, attribute fetch, evidence build + verify.
//! - [`error`] — the crate error type.

#![forbid(unsafe_code)]

pub mod binder;
pub mod client;
pub mod config;
pub mod error;
pub mod model;
pub mod transport;

pub use binder::{AttributeSignatureBinder, CadesAttributeBinder, attribute_bound_content_digest};
pub use client::{EvidenceReport, ScapClient};
pub use config::{AmaScapConfig, ScapCredentials, ScapEnvironment};
pub use error::ScapError;
pub use model::{
    AttributeProvider, CitizenRef, ProfessionalAttribute, ScapSignatureEvidence,
    ScapVerificationStatus, SubAttribute,
};
pub use transport::{
    AuthoritativeGrant, HttpScapTransport, MockScapTransport, ScapTransport, VerificationDecision,
};
