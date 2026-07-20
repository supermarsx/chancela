//! Ordered source chain (plan t23 §2.7): try several pull mechanisms in order — the built-in
//! official Diário da República diploma pair and/or auto-detected JSON mirror URLs — and let the
//! **first dataset that passes the gates and supersedes** win. Per-entry failures are recorded and
//! surfaced; a failing entry never aborts the chain and the chain never destroys the active catalog.
//!
//! This is the engine [`t23-e2`](../index.html) wires to `settings.cae_sources`: each settings entry
//! maps to a [`ChainEntry::Mirror`] (a URL + its declared/auto format), an optional
//! `cae_official_source` flag prepends [`ChainEntry::Official`], and the legacy `cae_update_url`
//! becomes a trailing `Auto` mirror entry.

use std::path::{Path, PathBuf};

use crate::catalog::CaeCatalog;
use crate::dataset::CaeProvenance;
use crate::error::CaeError;
use crate::{CaeRefreshOutcome, load_catalog};

use super::format::{CaeSourceFormat, parse_artifact};
use super::{
    DrPdfSource, IneOfficialSource, ObtainedDataset, OfficialCaeSource, OfficialSourceKind,
    PARSER_VERSION, fetch_bytes, now_rfc3339, obtain_and_supersede, sha256_hex,
};

/// Where a mirror artifact's bytes come from: a remote URL (fetched), a local file, or in-memory
/// bytes (dependency injection / tests). The transport is orthogonal to the format.
enum MirrorInput {
    Url(String),
    File(PathBuf),
    Bytes(Vec<u8>),
}

impl MirrorInput {
    fn label(&self) -> String {
        match self {
            MirrorInput::Url(url) => url.clone(),
            MirrorInput::File(path) => path.display().to_string(),
            MirrorInput::Bytes(_) => "<bytes>".to_owned(),
        }
    }
}

/// A JSON **mirror** source: fetch/read bytes, auto-detect (or use the declared) format, and parse to
/// a both-revision [`CaeDataset`]. Envelope or Simple JSON only — a `%PDF` artifact is rejected on
/// this path (the DR pair is the dedicated official source, not a single mirror URL). Implements
/// [`OfficialCaeSource`] with [`OfficialSourceKind::Mirror`] so it flows through the same
/// `obtain_and_supersede` pipeline as the official source.
pub struct MirrorArtifactSource {
    input: MirrorInput,
    format: CaeSourceFormat,
    /// Optional sha256 pin (lowercase hex) of the fetched bytes — a mismatch is a rejecting
    /// [`CaeError::Integrity`], mirroring the DR digest pin (plan t23 §2.7 `CaeSourceEntry.digest`).
    expected_digest: Option<String>,
    user_agent: String,
}

impl MirrorArtifactSource {
    /// A mirror fetched from a URL with the given format (`Auto` to sniff the bytes).
    pub fn from_url(url: impl Into<String>, format: CaeSourceFormat) -> Self {
        Self::new(MirrorInput::Url(url.into()), format)
    }

    /// A mirror read from a local file (DI / fixtures).
    pub fn from_file(path: impl Into<PathBuf>, format: CaeSourceFormat) -> Self {
        Self::new(MirrorInput::File(path.into()), format)
    }

    /// A mirror backed by in-memory bytes (tests).
    pub fn from_bytes(bytes: impl Into<Vec<u8>>, format: CaeSourceFormat) -> Self {
        Self::new(MirrorInput::Bytes(bytes.into()), format)
    }

    /// Pin the expected sha256 (lowercase hex) of the fetched artifact bytes.
    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.expected_digest = Some(digest.into());
        self
    }

    fn new(input: MirrorInput, format: CaeSourceFormat) -> Self {
        Self {
            input,
            format,
            expected_digest: None,
            user_agent: concat!("chancela-cae/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }

    /// A human/audit label (the URL or file path) for provenance + chain reporting.
    fn label(&self) -> String {
        self.input.label()
    }

    fn read_bytes(&self) -> Result<Vec<u8>, CaeError> {
        let bytes = match &self.input {
            MirrorInput::Url(url) => fetch_bytes(url, &self.user_agent)?,
            MirrorInput::File(path) => std::fs::read(path)
                .map_err(|e| CaeError::Http(format!("read {}: {e}", path.display())))?,
            MirrorInput::Bytes(bytes) => bytes.clone(),
        };
        if let Some(expected) = &self.expected_digest {
            let digest = sha256_hex(&bytes);
            if !digest.eq_ignore_ascii_case(expected.trim()) {
                return Err(CaeError::Integrity(format!(
                    "mirror artifact digest mismatch: expected {expected}, got {digest}"
                )));
            }
        }
        Ok(bytes)
    }
}

impl OfficialCaeSource for MirrorArtifactSource {
    fn kind(&self) -> OfficialSourceKind {
        OfficialSourceKind::Mirror
    }

    fn obtain(&self) -> Result<ObtainedDataset, CaeError> {
        let bytes = self.read_bytes()?;
        let mut dataset = parse_artifact(&bytes, self.format)?;
        // Stamp the mirror as the source of record for THIS obtain (plan t23 §2.4): the source URL and
        // the sha256 of the fetched bytes, overriding any provenance the hosted envelope carried.
        dataset.provenance = Some(CaeProvenance {
            source_kind: OfficialSourceKind::Mirror,
            source_url: self.label(),
            artifact_digest: sha256_hex(&bytes),
            retrieved_at: now_rfc3339(),
            parser_version: PARSER_VERSION.to_owned(),
        });
        // A mirror-hosted Simple-JSON array carries no intrinsic timestamp; parse_simple_json stamps
        // `generated_at` at read time so a genuinely different mirror supersedes while identical bytes
        // no-op via the content digest. Envelopes keep their own `generated_at`.
        Ok(ObtainedDataset { dataset })
    }
}

/// One entry in an ordered [`CaeSourceChain`].
pub enum ChainEntry {
    /// The built-in official Diário da República diploma pair (both PDFs, digest-pinned) — a complete
    /// two-revision catalog. Held as a ready [`DrPdfSource`].
    Official(DrPdfSource),
    /// The INE official source. INE publishes no downloadable bulk CAE artifact (t37), so this entry
    /// always fails honestly — placed before [`Official`](Self::Official) when INE is preferred, it
    /// records the failure and the DR pair fulfils the refresh. See [`IneOfficialSource`].
    Ine(IneOfficialSource),
    /// A JSON mirror (URL / file / bytes), format auto-detected or declared.
    Mirror(MirrorArtifactSource),
}

impl ChainEntry {
    /// The built-in official DR source entry (`DrPdfSource::official()`).
    pub fn official() -> Self {
        ChainEntry::Official(DrPdfSource::official())
    }

    /// The INE official source entry ([`IneOfficialSource`]) — always fails honestly (no viable INE
    /// bulk artifact, t37); the DR pair after it fulfils the refresh.
    pub fn ine() -> Self {
        ChainEntry::Ine(IneOfficialSource)
    }

    /// A mirror URL entry with the given format.
    pub fn mirror_url(url: impl Into<String>, format: CaeSourceFormat) -> Self {
        ChainEntry::Mirror(MirrorArtifactSource::from_url(url, format))
    }

    /// A short label identifying this entry in chain reporting.
    pub fn label(&self) -> String {
        match self {
            ChainEntry::Official(_) => "Diário da República (fonte oficial)".to_owned(),
            ChainEntry::Ine(_) => "INE (fonte oficial)".to_owned(),
            ChainEntry::Mirror(m) => m.label(),
        }
    }

    fn as_source(&self) -> &dyn OfficialCaeSource {
        match self {
            ChainEntry::Official(src) => src,
            ChainEntry::Ine(src) => src,
            ChainEntry::Mirror(m) => m,
        }
    }
}

/// An ordered list of sources tried first-to-last by [`obtain_from_chain`].
pub struct CaeSourceChain(pub Vec<ChainEntry>);

impl CaeSourceChain {
    /// Build a chain from an ordered list of entries.
    pub fn new(entries: Vec<ChainEntry>) -> Self {
        Self(entries)
    }

    /// Whether the chain has no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A single entry's failure while running the chain (fetch / parse / integrity / fidelity). Recorded
/// and surfaced in [`ChainOutcome::failures`]; never aborts the chain.
#[derive(Clone, Debug)]
pub struct ChainFailure {
    /// The entry's label.
    pub entry: String,
    /// The error, rendered for display/logging.
    pub error: String,
}

/// The result of running an ordered chain. The chain never fails the catalog: `catalog` is either the
/// superseding winner's or the retained known-good active catalog.
pub struct ChainOutcome {
    /// The active catalog after the chain ran.
    pub catalog: CaeCatalog,
    /// The refresh outcome (updated flag + resulting metadata + a human note).
    pub refresh: CaeRefreshOutcome,
    /// The label of the entry that superseded, if any (`None` = nothing newer was obtained).
    pub winner: Option<String>,
    /// Whether at least one entry produced a valid dataset (superseding or already up to date). Lets
    /// a caller distinguish "everything up to date" (`true`, no winner) from "all sources failed"
    /// (`false`) for status mapping.
    pub any_valid: bool,
    /// Per-entry failures, in entry order.
    pub failures: Vec<ChainFailure>,
}

/// Run an ordered source chain: for each entry in turn, obtain → structural integrity → full-count
/// fidelity → supersede. The **first entry that supersedes wins** (its cache is written and it is
/// returned immediately). An entry that fetches/parses but is not newer is recorded as valid and the
/// chain continues; an entry that fails any gate is recorded in `failures` and the chain continues.
/// If nothing supersedes, the active catalog is retained unchanged (`updated: false`).
///
/// This is infallible by construction — a bad or partial obtain can never replace or destroy the
/// known-good catalog (plan t23 §8.3).
pub fn obtain_from_chain(chain: &CaeSourceChain, data_dir: Option<&Path>) -> ChainOutcome {
    let mut failures = Vec::new();
    let mut any_valid = false;

    for entry in &chain.0 {
        let label = entry.label();
        match obtain_and_supersede(entry.as_source(), data_dir) {
            Ok((catalog, outcome)) => {
                any_valid = true;
                if outcome.updated {
                    return ChainOutcome {
                        catalog,
                        refresh: outcome,
                        winner: Some(label),
                        any_valid: true,
                        failures,
                    };
                }
                // Valid but not newer than the active catalog — keep trying later entries.
            }
            Err(e) => failures.push(ChainFailure {
                entry: label,
                error: e.to_string(),
            }),
        }
    }

    // No entry superseded: retain the active catalog and report why.
    let catalog = load_catalog(data_dir);
    let note = if any_valid {
        "todas as fontes obtidas estão atualizadas; catálogo ativo mantido".to_owned()
    } else if failures.is_empty() {
        "nenhuma fonte configurada".to_owned()
    } else {
        "todas as fontes configuradas falharam; catálogo ativo mantido".to_owned()
    };
    let refresh = CaeRefreshOutcome {
        updated: false,
        metadata: catalog.metadata().clone(),
        note,
    };
    ChainOutcome {
        catalog,
        refresh,
        winner: None,
        any_valid,
        failures,
    }
}
