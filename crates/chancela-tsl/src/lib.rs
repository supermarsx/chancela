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
//!    `NextUpdate` validity window. [`disk_cache::CachingTslSource`] backs that with a **durable**
//!    cache of the raw bytes, so a transient fetch failure falls back to the last good list instead
//!    of refusing the signature. It caches bytes, never a verdict: the cached copy is re-parsed and
//!    re-verified against the current anchors and algorithm policy on every use, and a copy served
//!    past its `NextUpdate` is reported through [`disk_cache::TslFetchProvenance`].
//! 4. [`query`] resolves an issuer certificate to a [`query::QualifiedStatus`]
//!    (`Granted`/`Withdrawn`/`Unknown`), which `chancela-signing` maps onto its
//!    `TrustedListStatus`. [`query::TslClient`] ties source + cache + query together.
//!
//! # XML-DSig signature validation (SIG-11, audit t41/C2)
//! The Trusted List's own XML-DSig signature is validated by
//! [`source::validate_tsl_signature`]. The [`query::TslClient`] calls this on every `refresh`
//! and refuses to return [`QualifiedStatus::Granted`] when the signature does not verify.
//!
//! Verifying the signature against the certificate the list *itself* carries only proves internal
//! consistency — a self-signed list passes. The list is the system's root of trust, so the signer
//! certificate is additionally **anchored** to a configured EU LOTL / national scheme signing
//! certificate ([`source::TslTrustAnchors`], sourced from `CHANCELA_TSL_TRUST_ANCHOR` /
//! `CHANCELA_TSL_TRUST_ANCHOR_SHA256`). This is **fail-closed**: when no anchor is configured,
//! every list is reported untrusted. Callers holding a configured anchor can call
//! [`source::validate_tsl_signature_with_anchors`] directly. See `crates/chancela-tsl/TESTING.md`
//! for the verification boundary.

#![forbid(unsafe_code)]

pub mod c14n;
pub mod cache;
pub mod certpath;
pub mod disk_cache;
pub mod error;
pub mod lotl;
pub mod parse;
pub mod query;
pub mod record;
pub mod source;
pub mod trust_store;

pub(crate) mod xmldsig;

pub use c14n::{C14nAlgorithm, canonicalize};
pub use cache::{CachedTsl, FALLBACK_TTL};
pub use certpath::{CertPath, PathBuildOptions, build_path};
pub use disk_cache::{
    ALL_TSL_CACHE_CODES, CODE_TSL_SERVED_FROM_CACHE, CODE_TSL_SERVED_FROM_STALE_CACHE,
    CachedTslBytes, CachingTslSource, DEFAULT_MAX_STALE, ENV_TSL_CACHE_MAX_STALE_HOURS,
    TSL_CACHE_DIR, TslCacheLoad, TslCacheRefusal, TslCacheServe, TslClock, TslDiskCache,
    TslFetchProvenance, TslProvenanceHandle, max_stale_from_env,
};
pub use error::{TslError, describe_error_chain};
pub use lotl::{
    AuthenticatedList, DEFAULT_LOTL_URL, ENV_LOTL_URL, bootstrap_member_tsl, ingest_lotl,
    ingest_member_tsl, member_pointer, member_pointer_in,
};
pub use parse::{
    DigitalIdentity, LocalizedText, OtherTslPointer, ServiceHistoryEntry, ServiceStatus,
    TrustService, TrustServiceProvider, TrustedList, parse_tsl,
};
pub use query::{
    QtstMatchDetails, QtstServiceMatch, QualifiedStatus, TslClient, qualified_esig_services,
    qualified_timestamp_services, resolve_esig_status, resolve_qtst_match_details,
    resolve_qtst_status,
};
pub use record::{
    RecordIdentifier, RecordIdentifierKind, RecordLookupField, RecordLookupInputKind,
    RecordLookupOutcome, RecordSearch, RecordStatusKind, TslRecord, TslRecordLookup,
    TslRecordLookupMatch, filter_records, lookup_records, trust_service_records, tsa_records,
};
pub use source::{
    BytesTslSource, DEFAULT_PT_TSL_URL, ENV_TSL_TRUST_ANCHOR, ENV_TSL_TRUST_ANCHOR_SHA256,
    ENV_TSL_URL, FileTslSource, HttpTslSource, TslSource, TslTrustAnchors, parse_anchor_certs,
    parse_hex_sha256, validate_tsl_signature, validate_tsl_signature_with_anchors,
    validate_tsl_signature_with_policy,
};
pub use trust_store::TslTrustStore;
/// Algorithm policy: which XML-DSig algorithms a Trusted List signature may be verified with, and
/// what a successful verification depended on. See [`xmldsig::TslAlgorithmPolicy`].
pub use xmldsig::{
    CODE_WEAK_DIGEST_PERMITTED, CODE_WEAK_SIGNATURE_METHOD_PERMITTED, KNOWN_LEGACY_ALGORITHMS,
    LEGACY_ECDSA_SHA1, LEGACY_RSA_SHA1, LEGACY_SHA1_DIGEST, TslAlgorithmPolicy, TslSignatureReport,
    WeakAlgorithmSite, WeakAlgorithmUse, extract_signer_cert,
};
