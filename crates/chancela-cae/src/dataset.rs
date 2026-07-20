//! The wire/file dataset envelope (§2.3) shared by the embedded dataset and any fetched update —
//! so an update is a drop-in replacement of the cache file with no schema drift.

use serde::{Deserialize, Serialize};

use crate::error::CaeError;
use crate::model::CaeEntry;
use crate::obtain::OfficialSourceKind;

/// The wire/file shape shared by the EMBEDDED dataset and any FETCHED update.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaeDataset {
    pub schema_version: u32,
    pub generated_at: String,
    pub source_note: String,
    pub rev3: Vec<CaeEntry>,
    pub rev4: Vec<CaeEntry>,
    /// Provenance of an OFFICIAL-source obtain (plan t23 §2.4). Additive and optional: the embedded
    /// dataset and any pre-t23 cache file omit it (`serde(default)` → `None`), so `CAE_SCHEMA_VERSION`
    /// stays `1` and every existing envelope still parses. Skipped on serialize when absent, so a
    /// cache written for the embedded dataset is byte-unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<CaeProvenance>,
}

/// Where an obtained dataset came from, recorded in the envelope for audit (plan t23 §2.4). For a
/// two-diploma Diário da República obtain, `source_url`/`artifact_digest` identify the **current
/// revision's** artifact (the CAE-Rev.4 diploma); both diplomas are named in the dataset's
/// `source_note`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaeProvenance {
    pub source_kind: OfficialSourceKind,
    pub source_url: String,
    /// sha256 of the fetched primary artifact (lowercase hex).
    pub artifact_digest: String,
    /// When the artifact was retrieved (RFC 3339).
    pub retrieved_at: String,
    /// The obtainer/parser version that produced this dataset.
    pub parser_version: String,
}

/// Current dataset schema version. Bumped only on a breaking change to [`CaeDataset`].
pub const CAE_SCHEMA_VERSION: u32 = 1;

/// Build time of the compiled-in dataset (RFC 3339). Committed, not build-time, so the embedded
/// digest and `generated_at` are stable and reproducible across builds.
const EMBEDDED_GENERATED_AT: &str = "2026-07-07T00:00:00Z";

/// Human note recording which official tables the embedded dataset was generated from.
const EMBEDDED_SOURCE_NOTE: &str = "Gerado a partir de DL 381/2007 (CAE-Rev.3) e DL 9/2025 \
     (CAE-Rev.4), Diário da República 1.ª série. Ver crates/chancela-cae/data/source/PROVENANCE.md.";

/// The two per-revision entry arrays, embedded verbatim (`include_str!`) and parsed lazily once.
const EMBEDDED_REV3: &str = include_str!("../data/cae_rev3.json");
const EMBEDDED_REV4: &str = include_str!("../data/cae_rev4.json");

impl CaeDataset {
    /// Assemble the compiled-in dataset from the two embedded revision arrays plus the committed
    /// metadata. Parsing errors surface as [`CaeError::Parse`] (they can only occur if the embedded
    /// JSON is corrupt, which the fidelity tests guard against).
    pub(crate) fn embedded() -> Result<Self, CaeError> {
        let rev3: Vec<CaeEntry> = serde_json::from_str(EMBEDDED_REV3)
            .map_err(|e| CaeError::Parse(format!("embedded cae_rev3.json: {e}")))?;
        let rev4: Vec<CaeEntry> = serde_json::from_str(EMBEDDED_REV4)
            .map_err(|e| CaeError::Parse(format!("embedded cae_rev4.json: {e}")))?;
        Ok(Self {
            schema_version: CAE_SCHEMA_VERSION,
            generated_at: EMBEDDED_GENERATED_AT.to_owned(),
            source_note: EMBEDDED_SOURCE_NOTE.to_owned(),
            rev3,
            rev4,
            provenance: None,
        })
    }

    /// Parse a dataset from raw bytes (a fetched update or a cache file). Errors as
    /// [`CaeError::Parse`].
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, CaeError> {
        serde_json::from_slice(bytes).map_err(|e| CaeError::Parse(e.to_string()))
    }
}
