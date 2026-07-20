//! The wire/file corpus envelope shared by the embedded corpus and any fetched update — so an
//! update is a drop-in replacement with no schema drift (mirrors [`chancela_cae::CaeDataset`]).

use serde::{Deserialize, Serialize};

use crate::error::LawError;
use crate::model::LawDiploma;

/// Current corpus schema version. Bumped only on a breaking change to [`LawCorpus`].
pub const LAW_SCHEMA_VERSION: u32 = 1;

/// Build time of the compiled-in corpus (RFC 3339). Committed, not build-time, so the embedded
/// digest and `generated_at` are stable and reproducible across builds.
const EMBEDDED_GENERATED_AT: &str = "2026-07-08T00:00:00Z";

/// Human note recording how the embedded corpus was seeded.
const EMBEDDED_SOURCE_NOTE: &str = "Esqueleto do corpus de legislação (t55-E1a): lista completa de \
     diplomas em escopo com os artigos citados pré-alocados a `Pending`. O texto verbatim é \
     obtido do Diário da República Eletrónico por diploma (t55-E1b). Ver \
     crates/chancela-law/data/source/PROVENANCE.md.";

/// The diploma array, embedded verbatim (`include_str!`) and parsed lazily once.
const EMBEDDED_DIPLOMAS: &str = include_str!("../data/law_corpus.json");

/// The wire/file shape shared by the EMBEDDED corpus and any FETCHED update.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LawCorpus {
    pub schema_version: u32,
    pub generated_at: String,
    pub source_note: String,
    pub diplomas: Vec<LawDiploma>,
    /// Provenance of an official-source obtain (mirrors `CaeProvenance`). Additive and optional:
    /// the embedded corpus omits it (`serde(default)` → `None`), so `LAW_SCHEMA_VERSION` stays `1`
    /// and every existing envelope still parses. Skipped on serialize when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<LawProvenance>,
}

/// Where an obtained corpus (or a per-diploma vendored batch) came from, recorded for audit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LawProvenance {
    /// A short kind tag, e.g. `"dre-consolidada"`, `"dre-pdf"`, `"eur-lex"`.
    pub source_kind: String,
    pub source_url: String,
    /// sha256 of the fetched primary artifact (lowercase hex).
    pub artifact_digest: String,
    /// When the artifact was retrieved (RFC 3339).
    pub retrieved_at: String,
    /// The obtainer/parser version that produced this corpus.
    pub parser_version: String,
}

impl LawCorpus {
    /// Assemble the compiled-in corpus from the embedded diploma array plus committed metadata.
    /// Parsing errors surface as [`LawError::Parse`] (they can only occur if the embedded JSON is
    /// corrupt, which the authenticity/shape tests guard against).
    pub(crate) fn embedded() -> Result<Self, LawError> {
        let diplomas: Vec<LawDiploma> = serde_json::from_str(EMBEDDED_DIPLOMAS)
            .map_err(|e| LawError::Parse(format!("embedded law_corpus.json: {e}")))?;
        Ok(Self {
            schema_version: LAW_SCHEMA_VERSION,
            generated_at: EMBEDDED_GENERATED_AT.to_owned(),
            source_note: EMBEDDED_SOURCE_NOTE.to_owned(),
            diplomas,
            provenance: None,
        })
    }

    /// Parse a corpus from raw bytes (a fetched update or a cache file). Errors as
    /// [`LawError::Parse`].
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, LawError> {
        serde_json::from_slice(bytes).map_err(|e| LawError::Parse(e.to_string()))
    }
}
