//! chancela-cae — the extensive Classificação Portuguesa das Atividades Económicas (CAE) library.
//!
//! Embeds the full official CAE table for **both** revisions (Rev.3 and Rev.4), every hierarchy
//! level (secção/divisão/grupo/classe/subclasse), so any CAE code printed on a certidão resolves
//! to its designation, level and revision. On top of the embedded dataset it offers
//! lookup/hierarchy/search plus a fetch-behind-trait + data-dir cache + integrity check +
//! non-blocking background refresh, mirroring `chancela-tsl`'s `TslSource`/`CachedTsl` pattern.
//!
//! The embedded dataset is generated from the official Diário da República diplomas by a committed,
//! reproducible generator (`data/source/gen_cae.py`) over the vendored source PDFs; see
//! `data/source/PROVENANCE.md`. Fidelity is enforced by the structural-count + spot-check tests.
//!
//! ## Layers
//! - [`CaeCatalog`] — immutable, indexed view over both revisions ([`CaeCatalog::embedded`] is the
//!   compiled-in dataset parsed once); [`lookup`](CaeCatalog::lookup) / [`hierarchy`](CaeCatalog::hierarchy)
//!   / [`children`](CaeCatalog::children) / [`search`](CaeCatalog::search).
//! - [`CaeSource`] — the fetch-behind-trait ([`HttpCaeSource`], [`FileCaeSource`], [`BytesCaeSource`]).
//! - Cache + auto-update — [`load_catalog`] (valid cache preferred over embedded), [`refresh`], and
//!   the non-blocking [`spawn_background_refresh`].

mod cache;
mod catalog;
mod dataset;
mod error;
mod model;
mod obtain;
mod source;

pub use cache::{
    CACHE_FILE, CachedCae, CaeRefreshOutcome, DEFAULT_CAE_TTL, load_catalog, refresh,
    spawn_background_refresh, write_cache_atomic,
};
pub use catalog::{CaeCatalog, CaeCounts, CaeLevelCounts, CaeMetadata, CaeOrigin};
pub use dataset::{CAE_SCHEMA_VERSION, CaeDataset, CaeProvenance};
pub use error::CaeError;
pub use model::{CaeEntry, CaeLevel, CaeRevision};
pub use obtain::{
    CaeSourceChain, CaeSourceFormat, CaeVerifier, CaeVersions, ChainEntry, ChainFailure,
    ChainOutcome, DR_REV3_PDF_SHA256, DR_REV3_PDF_URL, DR_REV4_PDF_SHA256, DR_REV4_PDF_URL,
    DrPdfSource, EXPECTED_REV3_COUNTS, EXPECTED_REV4_COUNTS, IneOfficialSource,
    MirrorArtifactSource, ObtainedDataset, OfficialCaeSource, OfficialSourceKind,
    PreferredOfficialSource, SICONF_BASE_URL, SMI_BASE_URL, SMI_CAE_REV3_VERSION,
    SMI_CAE_REV4_VERSION, SMI_VERSION_EXPORT_PATH, SiconfVerifier, SmiSource, SmiVersion,
    SmiVersionCatalog, VerifierFinding, default_official_chain, detect_format,
    obtain_and_supersede, obtain_from_chain, official_chain_for, parse_artifact,
    parse_smi_version_catalog, verify_fidelity,
};
pub use source::{BytesCaeSource, CaeSource, ENV_CAE_URL, FileCaeSource, HttpCaeSource};
