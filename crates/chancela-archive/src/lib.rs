//! `chancela-archive` — export-package model (spec 08).
//!
//! This crate is a **compiling stub**: it fixes the shape of the archival export package the
//! product must be able to emit, but does not implement package assembly. [`build_package`]
//! returns [`ArchiveError::NotImplemented`] rather than `todo!()`.
//!
//! The export package (DOC-20) MUST be ingestible by other archival/DMS systems and MUST
//! carry: checksums, provenance, rights metadata, language metadata, signing evidence, and
//! retention instructions. Preservation design follows DGLAB long-term guidance (DOC-21):
//! plan for preservability and controlled migration, maintaining integrity and usability
//! over time. Retention schedules and legal holds apply at the package level; a package
//! under legal hold MUST NOT be deletable through any retention rule (DOC-22).

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// A checksum over one packaged file (DOC-20 checksums).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChecksum {
    /// Path of the file within the package.
    pub path: String,
    /// Algorithm used, e.g. `"sha256"`.
    pub algorithm: String,
    /// Lower-case hex digest.
    pub hex_digest: String,
}

/// Where a piece of packaged content came from (DOC-20 provenance; DOC-32 explainability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProvenanceSource {
    /// Content originated from a sealed act.
    SealedAct,
    /// Content originated from a registry import (e.g. certidão permanente).
    RegistryImport,
    /// Content was entered directly by a user.
    UserEntry,
}

/// Provenance record tying packaged content back to a source (DOC-32: every item traces back).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The kind of source.
    pub source: ProvenanceSource,
    /// A reference into that source (act id, import id, …).
    pub reference: String,
    /// When the content was captured into the platform.
    #[serde(with = "time::serde::rfc3339::option")]
    pub captured_at: Option<time::OffsetDateTime>,
}

/// Rights/usage metadata to travel with the package (DOC-20 rights metadata).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RightsMetadata {
    /// Rights holder, if recorded.
    pub holder: Option<String>,
    /// Licence or usage statement.
    pub license: Option<String>,
    /// Free-form access/confidentiality note.
    pub access_note: Option<String>,
}

/// Retention/legal-hold instructions carried at package level (DOC-22; LEG-10).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RetentionInstructions {
    /// Retention schedule identifier, if any.
    pub schedule_id: Option<String>,
    /// Earliest date the package may be reviewed for disposal.
    #[serde(with = "time::serde::rfc3339::option")]
    pub review_after: Option<time::OffsetDateTime>,
    /// When true, the package is under legal hold and MUST NOT be deleted by any retention
    /// rule (DOC-22).
    pub legal_hold: bool,
}

impl RetentionInstructions {
    /// Whether the package may be considered for retention-driven disposal. A legal hold
    /// always blocks disposal regardless of schedule (DOC-22).
    pub fn is_disposable(&self) -> bool {
        !self.legal_hold
    }
}

/// The long-term preservation level targeted for the package (DOC-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PreservationLevel {
    /// Bit-level preservation only (fixity maintained, no format guarantees).
    BitLevel,
    /// Managed preservation with controlled format migration (DGLAB guidance).
    Managed,
}

/// The manifest describing everything in an export package (DOC-20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// The entity the package belongs to.
    pub entity_id: uuid::Uuid,
    /// The book the packaged acts belong to.
    pub book_id: uuid::Uuid,
    /// The acts included in the package.
    pub act_ids: Vec<uuid::Uuid>,
    /// Per-file checksums (DOC-20 checksums).
    pub checksums: Vec<FileChecksum>,
    /// Provenance records (DOC-20 provenance).
    pub provenance: Vec<Provenance>,
    /// Rights metadata (DOC-20 rights metadata).
    pub rights: RightsMetadata,
    /// BCP-47 language tags present in the package (DOC-20 language metadata).
    pub languages: Vec<String>,
    /// Retention instructions (DOC-22).
    pub retention: RetentionInstructions,
    /// Targeted preservation level (DOC-21).
    pub preservation_level: PreservationLevel,
}

/// A fully assembled export package ready to hand to an external archival/DMS system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPackage {
    /// Stable id of this package.
    pub id: uuid::Uuid,
    /// The manifest (checksums, provenance, rights, language, retention, preservation).
    pub manifest: PackageManifest,
    /// When the package was built.
    #[serde(with = "time::serde::rfc3339::option")]
    pub built_at: Option<time::OffsetDateTime>,
}

/// Errors from the (stubbed) archive subsystem.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArchiveError {
    /// Package assembly is a stub and not yet implemented.
    #[error("archive packaging not implemented (stub crate)")]
    NotImplemented,
    /// A required piece of evidence (signed PDF, validation report, …) was missing (DOC-03).
    #[error("required preservation artifact is missing: {0}")]
    MissingArtifact(String),
}

/// Build an export package from a manifest (DOC-20).
///
/// TODO: gather the sealed acts' signed PDFs, validation reports, structured metadata, and
/// attachment manifests (DOC-03); compute checksums; embed signing evidence; and emit a
/// package ingestible by external archival systems following DGLAB guidance (DOC-21).
pub fn build_package(_manifest: PackageManifest) -> Result<ExportPackage, ArchiveError> {
    Err(ArchiveError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> PackageManifest {
        PackageManifest {
            entity_id: uuid::Uuid::nil(),
            book_id: uuid::Uuid::nil(),
            act_ids: vec![],
            checksums: vec![FileChecksum {
                path: "act-1.pdf".into(),
                algorithm: "sha256".into(),
                hex_digest: "00".into(),
            }],
            provenance: vec![Provenance {
                source: ProvenanceSource::SealedAct,
                reference: "act:1".into(),
                captured_at: None,
            }],
            rights: RightsMetadata::default(),
            languages: vec!["pt-PT".into()],
            retention: RetentionInstructions::default(),
            preservation_level: PreservationLevel::Managed,
        }
    }

    #[test]
    fn build_package_is_stubbed() {
        assert_eq!(
            build_package(sample_manifest()),
            Err(ArchiveError::NotImplemented)
        );
    }

    #[test]
    fn legal_hold_blocks_disposal() {
        // DOC-22: a package under legal hold must never be disposable.
        let mut retention = RetentionInstructions::default();
        assert!(retention.is_disposable());
        retention.legal_hold = true;
        assert!(!retention.is_disposable());
    }

    #[test]
    fn manifest_serde_round_trip() {
        let manifest = sample_manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: PackageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }
}
