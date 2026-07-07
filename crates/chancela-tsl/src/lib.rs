//! `chancela-tsl` — Portuguese Trusted List ingestion + qualified-status query (spec 04).
//!
//! This crate ingests the Portuguese Trusted List (ETSI TS 119 612) published by the Gabinete
//! Nacional de Seguranca and answers one question the signing subsystem needs before it trusts a
//! qualified certificate: **is this certificate's issuer a currently-qualified QTSP for
//! e-signatures?** (SIG-10..13). It does so entirely offline against a bundled fixture in tests;
//! the live fetch is feature-gated and never runs in CI.
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
//! # Scope (this phase)
//! Parsing, status resolution, caching and querying are implemented and covered by
//! fixture-based offline tests. **Validating the Trusted List's own XML-DSig signature (SIG-11)
//! is an explicit phase-2 stub** — see [`source::validate_tsl_signature`] and
//! `crates/chancela-tsl/TESTING.md`.

pub mod cache;
pub mod error;
pub mod parse;
pub mod query;
pub mod source;

pub use cache::{CachedTsl, FALLBACK_TTL};
pub use error::TslError;
pub use parse::{
    DigitalIdentity, ServiceStatus, TrustService, TrustServiceProvider, TrustedList, parse_tsl,
};
pub use query::{QualifiedStatus, TslClient, qualified_esig_services, resolve_esig_status};
pub use source::{
    BytesTslSource, DEFAULT_PT_TSL_URL, ENV_TSL_URL, FileTslSource, HttpTslSource, TslSource,
    validate_tsl_signature,
};
