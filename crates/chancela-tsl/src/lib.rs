//! `chancela-tsl` — Portuguese Trusted List ingestion + qualified-status query (spec 04).
//!
//! This crate ingests the Portuguese Trusted List (ETSI TS 119 612) published by the Gabinete
//! Nacional de Seguranca and answers technical trusted-list status questions the signing subsystem
//! needs before it trusts qualified evidence: **is this certificate's issuer a currently-qualified
//! QTSP for e-signatures?** and **is this TSA identity a currently-granted qualified timestamp
//! service (`TSA/QTST`)?** (SIG-10..13/SIG-22). It does so entirely offline against a bundled
//! fixture in tests; the live fetch is feature-gated and never runs in CI.
//!
//! # Pipeline
//! 1. [`source::TslSource`] fetches the raw XML — [`source::HttpTslSource`] over the network,
//!    [`source::FileTslSource`]/[`source::BytesTslSource`] for fixtures and pinned copies.
//! 2. [`parse::parse_tsl`] turns the XML into a [`parse::TrustedList`] of
//!    [`parse::TrustServiceProvider`]s / [`parse::TrustService`]s, tolerating the list's many
//!    optional elements (defensive parsing).
//! 3. [`cache::CachedTsl`] holds the parsed list and reports staleness against the list's own
//!    `NextUpdate` validity window.
//! 4. [`query`] resolves an issuer certificate to a [`query::QualifiedStatus`]
//!    (`Granted`/`Withdrawn`/`Unknown`), which `chancela-signing` maps onto its
//!    `TrustedListStatus`. [`query::TslClient`] ties source + cache + query together.
//!
//! # XML-DSig signature validation (SIG-11)
//! The Trusted List's own XML-DSig signature is validated by
//! [`source::validate_tsl_signature`]. The [`query::TslClient`] calls this on every `refresh`
//! and refuses to return [`QualifiedStatus::Granted`] when the signature does not verify —
//! see `crates/chancela-tsl/TESTING.md` for the verification boundary.

#![forbid(unsafe_code)]

pub mod cache;
pub mod error;
pub mod parse;
pub mod query;
pub mod record;
pub mod source;

pub(crate) mod xmldsig;

pub use cache::{CachedTsl, FALLBACK_TTL};
pub use error::TslError;
pub use parse::{
    DigitalIdentity, LocalizedText, ServiceHistoryEntry, ServiceStatus, TrustService,
    TrustServiceProvider, TrustedList, parse_tsl,
};
pub use query::{
    QualifiedStatus, TslClient, qualified_esig_services, qualified_timestamp_services,
    resolve_esig_status, resolve_qtst_status,
};
pub use record::{
    RecordIdentifier, RecordIdentifierKind, RecordSearch, RecordStatusKind, TslRecord,
    filter_records, trust_service_records, tsa_records,
};
pub use source::{
    BytesTslSource, DEFAULT_PT_TSL_URL, ENV_TSL_URL, FileTslSource, HttpTslSource, TslSource,
    validate_tsl_signature,
};
