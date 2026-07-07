//! Immutable, indexed catalog over both revisions plus provenance metadata (§2.2).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dataset::{CAE_SCHEMA_VERSION, CaeDataset, CaeProvenance};
use crate::error::CaeError;
use crate::model::{CaeEntry, CaeLevel, CaeRevision};

/// Per-level node counts for one revision (the structural-integrity gate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaeLevelCounts {
    pub seccao: u32,
    pub divisao: u32,
    pub grupo: u32,
    pub classe: u32,
    pub subclasse: u32,
}

impl CaeLevelCounts {
    /// Total nodes across all five levels.
    pub fn total(&self) -> u32 {
        self.seccao + self.divisao + self.grupo + self.classe + self.subclasse
    }
}

/// Per-revision node counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaeCounts {
    pub rev3: CaeLevelCounts,
    pub rev4: CaeLevelCounts,
}

/// Where the active catalog was loaded from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaeOrigin {
    Embedded,
    Cache,
}

/// Provenance + integrity metadata for a loaded catalog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaeMetadata {
    pub schema_version: u32,
    pub generated_at: String,
    pub source_note: String,
    pub digest: String,
    pub origin: CaeOrigin,
    pub counts: CaeCounts,
    /// Official-source provenance (plan t23 §2.4), surfaced from the dataset envelope. `None` for the
    /// embedded catalog and any pre-t23 cache; `Some` for a catalog obtained from an official source.
    /// Skipped on serialize when absent so existing API/contract shapes are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<CaeProvenance>,
}

/// Immutable, indexed view over the entries of both revisions plus provenance metadata.
#[derive(Clone, Debug)]
pub struct CaeCatalog {
    entries: Vec<CaeEntry>,
    /// `(revision, code)` → index into `entries`.
    index: HashMap<(CaeRevision, String), usize>,
    /// `(revision, parent_code)` → indices of that parent's direct children, in stored order.
    children: HashMap<(CaeRevision, String), Vec<usize>>,
    metadata: CaeMetadata,
}

impl CaeCatalog {
    /// The compiled-in dataset, parsed and validated once (`OnceLock` over the embedded JSON).
    ///
    /// Panics only if the embedded dataset is corrupt — a build-time invariant the fidelity tests
    /// guarantee, so callers treat this as infallible.
    pub fn embedded() -> &'static CaeCatalog {
        static EMBEDDED: OnceLock<CaeCatalog> = OnceLock::new();
        EMBEDDED.get_or_init(|| {
            let ds = CaeDataset::embedded().expect("embedded CAE dataset must parse");
            CaeCatalog::from_dataset(ds).expect("embedded CAE dataset must pass integrity")
        })
    }

    /// Build + validate a catalog from a dataset (structural counts, parent resolution, digest).
    /// The resulting metadata reports [`CaeOrigin::Embedded`]; the cache loader relabels it.
    pub fn from_dataset(ds: CaeDataset) -> Result<Self, CaeError> {
        Self::from_dataset_with_origin(ds, CaeOrigin::Embedded)
    }

    pub(crate) fn from_dataset_with_origin(
        ds: CaeDataset,
        origin: CaeOrigin,
    ) -> Result<Self, CaeError> {
        let rev3_counts = validate_revision(&ds.rev3, CaeRevision::Rev3)?;
        let rev4_counts = validate_revision(&ds.rev4, CaeRevision::Rev4)?;

        let digest = compute_digest(&ds);
        let provenance = ds.provenance;

        // Flatten both revisions into one indexed store.
        let mut entries = ds.rev3;
        entries.extend(ds.rev4);

        let mut index = HashMap::with_capacity(entries.len());
        let mut children: HashMap<(CaeRevision, String), Vec<usize>> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            index.insert((e.revision, e.code.clone()), i);
            if let Some(parent) = &e.parent {
                children
                    .entry((e.revision, parent.clone()))
                    .or_default()
                    .push(i);
            }
        }

        Ok(Self {
            entries,
            index,
            children,
            metadata: CaeMetadata {
                schema_version: ds.schema_version,
                generated_at: ds.generated_at,
                source_note: ds.source_note,
                digest,
                origin,
                counts: CaeCounts {
                    rev3: rev3_counts,
                    rev4: rev4_counts,
                },
                provenance,
            },
        })
    }

    /// Resolve a code. With `revision = None`, try Rev.4 first then Rev.3 (the returned entry
    /// reports which revision matched). Case-insensitive for secção letters; digits verbatim.
    pub fn lookup(&self, code: &str, revision: Option<CaeRevision>) -> Option<&CaeEntry> {
        let code = normalize_code(code);
        match revision {
            Some(rev) => self.get(rev, &code),
            None => self
                .get(CaeRevision::Rev4, &code)
                .or_else(|| self.get(CaeRevision::Rev3, &code)),
        }
    }

    /// Ancestor chain secção→…→`code` (inclusive) within `revision`, via the `parent` walk.
    /// Empty if `code` is unknown in `revision`.
    pub fn hierarchy(&self, code: &str, revision: CaeRevision) -> Vec<&CaeEntry> {
        let mut chain = Vec::new();
        let mut cursor = normalize_code(code);
        // A CAE chain is at most 5 deep; the bound also guards against a malformed cycle.
        for _ in 0..8 {
            let Some(entry) = self.get(revision, &cursor) else {
                chain.clear();
                return chain;
            };
            chain.push(entry);
            match &entry.parent {
                Some(parent) => cursor = normalize_code(parent),
                None => break,
            }
        }
        chain.reverse();
        chain
    }

    /// Direct children of `code` within `revision`, in canonical order. Empty if none/unknown.
    pub fn children(&self, code: &str, revision: CaeRevision) -> Vec<&CaeEntry> {
        let code = normalize_code(code);
        self.children
            .get(&(revision, code))
            .map(|idxs| idxs.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Accent-folded substring match over code + designation; `limit` caps the result count.
    /// When `revision` is `Some`, only that revision is searched. Results are in catalog order
    /// (Rev.3 then Rev.4, hierarchically).
    pub fn search(
        &self,
        query: &str,
        revision: Option<CaeRevision>,
        limit: usize,
    ) -> Vec<&CaeEntry> {
        let needle = fold(query);
        if needle.is_empty() || limit == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        for e in &self.entries {
            if revision.is_some_and(|r| r != e.revision) {
                continue;
            }
            if fold(&e.code).contains(&needle) || fold(&e.designation).contains(&needle) {
                out.push(e);
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }

    /// The active catalog's provenance + integrity metadata.
    pub fn metadata(&self) -> &CaeMetadata {
        &self.metadata
    }

    fn get(&self, revision: CaeRevision, code: &str) -> Option<&CaeEntry> {
        self.index
            .get(&(revision, code.to_owned()))
            .map(|&i| &self.entries[i])
    }
}

impl Default for CaeCatalog {
    fn default() -> Self {
        Self::embedded().clone()
    }
}

/// Normalize a lookup code to its canonical stored form: trimmed, ASCII-uppercased (a no-op for
/// digit codes, so secção letters match case-insensitively while digits compare verbatim).
fn normalize_code(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

/// Validate one revision's entries and return its per-level counts. Enforces: every entry belongs
/// to `revision`; its declared level matches its code shape; codes are unique; and every parent
/// resolves within the revision with the correct relationship (divisão→secção; grupo/classe/
/// subclasse→the code-prefix one level up).
fn validate_revision(
    entries: &[CaeEntry],
    revision: CaeRevision,
) -> Result<CaeLevelCounts, CaeError> {
    let mut by_code: HashMap<&str, &CaeEntry> = HashMap::with_capacity(entries.len());
    for e in entries {
        if by_code.insert(&e.code, e).is_some() {
            return Err(CaeError::Integrity(format!(
                "{revision:?}: duplicate code {}",
                e.code
            )));
        }
    }

    let mut counts = CaeLevelCounts {
        seccao: 0,
        divisao: 0,
        grupo: 0,
        classe: 0,
        subclasse: 0,
    };

    for e in entries {
        if e.revision != revision {
            return Err(CaeError::Integrity(format!(
                "{revision:?}: entry {} tagged {:?}",
                e.code, e.revision
            )));
        }
        match CaeLevel::from_code(&e.code) {
            Some(shape) if shape == e.level => {}
            other => {
                return Err(CaeError::Integrity(format!(
                    "{revision:?}: code {} shape implies {:?}, declared {:?}",
                    e.code, other, e.level
                )));
            }
        }
        validate_parent(e, &by_code, revision)?;
        match e.level {
            CaeLevel::Seccao => counts.seccao += 1,
            CaeLevel::Divisao => counts.divisao += 1,
            CaeLevel::Grupo => counts.grupo += 1,
            CaeLevel::Classe => counts.classe += 1,
            CaeLevel::Subclasse => counts.subclasse += 1,
        }
    }
    Ok(counts)
}

fn validate_parent(
    e: &CaeEntry,
    by_code: &HashMap<&str, &CaeEntry>,
    revision: CaeRevision,
) -> Result<(), CaeError> {
    let integrity = |msg: String| Err(CaeError::Integrity(format!("{revision:?}: {msg}")));

    match e.level {
        CaeLevel::Seccao => {
            if e.parent.is_some() {
                return integrity(format!("secção {} must have no parent", e.code));
            }
        }
        level => {
            let Some(parent) = &e.parent else {
                return integrity(format!("{} ({level:?}) has no parent", e.code));
            };
            let Some(parent_entry) = by_code.get(parent.as_str()) else {
                return integrity(format!("{} parent {parent} does not resolve", e.code));
            };
            let expected_parent_level = match level {
                CaeLevel::Divisao => CaeLevel::Seccao,
                CaeLevel::Grupo => CaeLevel::Divisao,
                CaeLevel::Classe => CaeLevel::Grupo,
                CaeLevel::Subclasse => CaeLevel::Classe,
                CaeLevel::Seccao => unreachable!(),
            };
            if parent_entry.level != expected_parent_level {
                return integrity(format!(
                    "{} parent {parent} is {:?}, expected {expected_parent_level:?}",
                    e.code, parent_entry.level
                ));
            }
            // Divisão parents are secção letters (not a code prefix); the deeper levels must be the
            // code with its last digit removed.
            if level != CaeLevel::Divisao && e.code.get(..e.code.len() - 1) != Some(parent.as_str())
            {
                return integrity(format!("{} parent {parent} is not its code prefix", e.code));
            }
        }
    }
    Ok(())
}

/// A deterministic, order-independent sha256 of the dataset content (lowercase hex). Two datasets
/// with the same nodes hash identically regardless of entry ordering, so it identifies the data.
fn compute_digest(ds: &CaeDataset) -> String {
    let mut rows: Vec<String> = Vec::with_capacity(ds.rev3.len() + ds.rev4.len());
    for e in ds.rev3.iter().chain(&ds.rev4) {
        rows.push(format!(
            "{:?}\t{}\t{:?}\t{}\t{}",
            e.revision,
            e.code,
            e.level,
            e.parent.as_deref().unwrap_or(""),
            e.designation
        ));
    }
    rows.sort();
    let mut hasher = Sha256::new();
    hasher.update(ds.schema_version.to_le_bytes());
    for row in rows {
        hasher.update(row.as_bytes());
        hasher.update(b"\n");
    }
    let mut hex = String::with_capacity(64);
    for b in hasher.finalize() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Accent-fold + lowercase for accent-insensitive search (mirrors the `fold` idiom in
/// `chancela-registry::parse`).
fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'u',
            'ç' | 'Ç' => 'c',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

/// `CAE_SCHEMA_VERSION` is re-exported at the crate root; assert the embedded dataset matches so a
/// silent schema drift is caught at compile-adjacent test time rather than at runtime.
const _: () = assert!(CAE_SCHEMA_VERSION == 1);
