//! `chancela-archive` - deterministic preservation export packages.
//!
//! This first package slice emits a simple ZIP container:
//! `manifest.json` is written first, followed by content members ordered by
//! their package path. The manifest carries package identifiers, preservation
//! metadata, and SHA-256 fixity data for each packaged member.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{Cursor, Read, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "manifest.json";
const SHA256: &str = "sha256";
const PDF_CONTENT_TYPE: &str = "application/pdf";
const JSON_CONTENT_TYPE: &str = "application/json";
pub const PRESERVATION_INTERCHANGE_PROFILE: &str =
    "chancela-internal-dglab-aligned-preservation-metadata/v1";
pub const LOCAL_DGLAB_INTERCHANGE_MANIFEST_SCHEMA: &str =
    "chancela-local-dglab-interchange-manifest/v1";
pub const LOCAL_DGLAB_INTERCHANGE_MANIFEST_PROFILE: &str = LOCAL_DGLAB_INTERCHANGE_MANIFEST_SCHEMA;
pub const DEFAULT_PACKAGE_TYPE: &str = "chancela-internal-preservation-package";
pub const DEFAULT_PACKAGE_VERSION: &str = "1";
const EVIDENCE_INDEX_PATH: &str = "evidence/index.json";
pub const READABILITY_DOCUMENTATION_PATH: &str = "readability/README.md";
pub const READABILITY_KEY_PACKAGE_PATH: &str = "readability/decryption-material.jwe";
const DEFAULT_PRODUCER_NAME: &str = "Chancela";
const DEFAULT_PRODUCER_SYSTEM: &str = "chancela-archive";
const MAX_READABILITY_JWE_BYTES: usize = 65_536;
const MAX_READABILITY_INSTRUCTIONS_BYTES: usize = 8_192;

/// A checksum over one packaged file (DOC-20 checksums).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChecksum {
    /// Algorithm used, currently always `"sha256"`.
    pub algorithm: String,
    /// Lower-case hex digest.
    pub hex_digest: String,
}

/// The role a file plays inside the preservation package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PackageFileRole {
    /// PDF/A rendition of a document.
    PdfA,
    /// Signing report supplied by a signing/validation subsystem.
    SigningReport,
    /// Evidence report supplied by an external validation or archival system.
    EvidenceReport,
    /// Structured metadata sidecar.
    Metadata,
    /// Human-readable instructions for a portable legal-archive transfer (ARC-32).
    ReadabilityDocumentation,
    /// Client-produced, encrypted portable key package. Never an unwrapped/raw key.
    EncryptedDecryptionMaterial,
    /// Other caller-supplied content.
    Other,
}

/// One file declared in the package manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageFile {
    /// Path of the file within the ZIP package.
    pub path: String,
    /// Role of this member in the preservation package.
    pub role: PackageFileRole,
    /// IANA media type of the member.
    pub content_type: String,
    /// File size in bytes.
    pub byte_len: u64,
    /// SHA-256 fixity data.
    pub checksum: FileChecksum,
    /// Act this file belongs to, if known by the caller.
    pub act_id: Option<uuid::Uuid>,
    /// Document this file belongs to, if known by the caller.
    pub document_id: Option<uuid::Uuid>,
}

/// A caller-supplied package member, including bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFileInput {
    /// Path of the file within the ZIP package.
    pub path: String,
    /// Role of this member in the preservation package.
    pub role: PackageFileRole,
    /// IANA media type of the member.
    pub content_type: String,
    /// File bytes to package.
    pub bytes: Vec<u8>,
    /// Act this file belongs to, if known by the caller.
    pub act_id: Option<uuid::Uuid>,
    /// Document this file belongs to, if known by the caller.
    pub document_id: Option<uuid::Uuid>,
}

impl PackageFileInput {
    /// Create a package member with an explicit path and content type.
    pub fn new(
        path: impl Into<String>,
        role: PackageFileRole,
        content_type: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            path: path.into(),
            role,
            content_type: content_type.into(),
            bytes: bytes.into(),
            act_id: None,
            document_id: None,
        }
    }

    /// Create a PDF/A document member under `documents/{document_id}.pdf`.
    ///
    /// This builder does not validate PDF/A conformance; callers must provide
    /// bytes already produced by the document/PDF subsystem.
    pub fn pdfa_document(
        document_id: uuid::Uuid,
        act_id: Option<uuid::Uuid>,
        pdfa_bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            path: format!("documents/{document_id}.pdf"),
            role: PackageFileRole::PdfA,
            content_type: PDF_CONTENT_TYPE.to_owned(),
            bytes: pdfa_bytes.into(),
            act_id,
            document_id: Some(document_id),
        }
    }

    /// Create a signing report sidecar under `signing/{document_id}.json`.
    pub fn signing_report(document_id: uuid::Uuid, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: format!("signing/{document_id}.json"),
            role: PackageFileRole::SigningReport,
            content_type: JSON_CONTENT_TYPE.to_owned(),
            bytes: bytes.into(),
            act_id: None,
            document_id: Some(document_id),
        }
    }

    /// Create an evidence report sidecar under `evidence/{document_id}.json`.
    pub fn evidence_report(document_id: uuid::Uuid, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: format!("evidence/{document_id}.json"),
            role: PackageFileRole::EvidenceReport,
            content_type: JSON_CONTENT_TYPE.to_owned(),
            bytes: bytes.into(),
            act_id: None,
            document_id: Some(document_id),
        }
    }

    /// Attach this member to an act id.
    pub fn with_act_id(mut self, act_id: uuid::Uuid) -> Self {
        self.act_id = Some(act_id);
        self
    }

    /// Attach this member to a document id.
    pub fn with_document_id(mut self, document_id: uuid::Uuid) -> Self {
        self.document_id = Some(document_id);
        self
    }
}

/// Where a piece of packaged content came from (DOC-20 provenance; DOC-32 explainability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProvenanceSource {
    /// Content originated from a sealed act.
    SealedAct,
    /// Content originated from a registry import (e.g. certidao permanente).
    RegistryImport,
    /// Content was entered directly by a user.
    UserEntry,
}

/// Provenance record tying packaged content back to a source (DOC-32: every item traces back).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The kind of source.
    pub source: ProvenanceSource,
    /// A reference into that source (act id, import id, ...).
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

/// Producer metadata for the DGLAB-aligned internal interchange section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerMetadata {
    /// Human-facing producer/operator name.
    pub name: String,
    /// Source system that assembled the package.
    pub system: String,
}

impl Default for ProducerMetadata {
    fn default() -> Self {
        Self {
            name: DEFAULT_PRODUCER_NAME.to_owned(),
            system: DEFAULT_PRODUCER_SYSTEM.to_owned(),
        }
    }
}

/// Classification placeholders aligned with DGLAB archival description concepts.
///
/// Chancela does not assign official DGLAB classification codes in this slice; callers may
/// populate these optional fields when their archive authority supplies them.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClassificationMetadata {
    /// Classification plan or scheme identifier, when known.
    pub scheme: Option<String>,
    /// Classification code, when known.
    pub code: Option<String>,
    /// Human-readable class title, when known.
    pub title: Option<String>,
    /// Sensitivity/confidentiality marker, when known.
    pub sensitivity: Option<String>,
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

/// Provenance summary for the DGLAB-aligned internal interchange section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceSummary {
    /// Source system that supplied the packaged records.
    pub source_system: String,
    /// Number of manifest provenance records.
    pub record_count: usize,
    /// Number of provenance records with a capture timestamp.
    pub captured_record_count: usize,
}

/// Fixity summary for the DGLAB-aligned internal interchange section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixitySummary {
    /// Fixity algorithm used for every declared package member.
    pub algorithm: String,
    /// Manifest member that carries per-file fixity data.
    pub manifest_path: String,
    /// Number of declared content members.
    pub file_count: usize,
    /// Sum of declared content-member byte lengths.
    pub total_byte_len: u64,
}

/// Legal-archive readability mode recorded in the internal manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LegalArchiveReadabilityMode {
    /// Manifest-only metadata: no decryption material, import proof, or legal-archive claim.
    #[default]
    ManifestOnly,
    /// A trusted client decrypted the archive before transfer and included transfer documentation.
    ClientDecryptedTransfer,
    /// Ciphertext travels with a portable encrypted key package and transfer documentation.
    EncryptedTransferWithPortableKeyPackage,
}

/// Readability and ZK/GDPR caveat metadata. Claim-like flags remain fail-closed: external import
/// verification and legal-archive certification cannot be asserted by this package builder, and ZK
/// never removes GDPR obligations (ARC-33 / LEG-13).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReadabilityCaveatMetadata {
    /// Conservative readability mode for this internal package manifest.
    pub legal_archive_readability_mode: LegalArchiveReadabilityMode,
    /// True only for `encrypted_transfer_with_portable_key_package`, where the declared member is
    /// encrypted material rather than a raw key.
    pub decryption_material_included: bool,
    /// Must remain false: no import by an external DMS/archive has been verified.
    pub external_import_verified: bool,
    /// Must remain false: this package does not certify a legal archive.
    pub legal_archive_certified: bool,
    /// True only for one of the two explicit client-produced ZK transfer modes.
    pub zk_repository_mode: bool,
    /// Must remain false: ZK does not remove GDPR obligations (LEG-13).
    pub zk_removes_gdpr_obligations: bool,
    /// Source repository for an explicit ZK readability transfer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_repository_id: Option<uuid::Uuid>,
    /// Required human-readable transfer instructions for explicit readability modes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_path: Option<String>,
    /// Required encrypted JWE material path for the encrypted transfer mode only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decryption_material_path: Option<String>,
}

/// Client-side readability export selection (ARC-32). The server-safe default remains
/// [`ManifestOnly`](ReadabilityExport::ManifestOnly). Explicit variants are intended to be called
/// inside a trusted desktop/browser boundary after user re-authentication.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReadabilityExport {
    /// No decryption material or transfer instructions.
    #[default]
    ManifestOnly,
    /// A trusted client has already decrypted the archive bytes being packaged.
    ClientDecryptedTransfer { source_repository_id: uuid::Uuid },
    /// The archive remains encrypted. `portable_key_package_jwe` is a compact JWE produced by the
    /// trusted client; the recipient secret/private key must travel out-of-band.
    EncryptedTransferWithPortableKeyPackage {
        source_repository_id: uuid::Uuid,
        portable_key_package_jwe: String,
        recipient_instructions: String,
    },
}

/// Internal archival interchange metadata aligned with DGLAB concepts.
///
/// This is intentionally not an official DGLAB interchange claim. It is a stable, structured
/// Chancela side of the manifest carrying producer, package type/version, preservation,
/// classification/retention placeholders, provenance/fixity, rights, and language metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreservationInterchangeMetadata {
    /// Internal metadata profile identifier.
    pub profile: String,
    /// Must remain false: this package is not an official DGLAB interchange package.
    pub official_dglab_interchange: bool,
    /// Must remain false: this package does not claim DGLAB certification.
    pub dglab_certification_claimed: bool,
    /// Manifest-only readability and ZK/GDPR caveats.
    #[serde(default)]
    pub readability_caveats: ReadabilityCaveatMetadata,
    /// Producer/operator and source-system metadata.
    pub producer: ProducerMetadata,
    /// Internal package type.
    pub package_type: String,
    /// Internal package type version.
    pub package_version: String,
    /// Targeted preservation level.
    pub preservation_level: PreservationLevel,
    /// Classification placeholders.
    pub classification: ClassificationMetadata,
    /// Retention/legal-hold instructions mirrored from the manifest.
    pub retention: RetentionInstructions,
    /// Provenance summary mirrored from the manifest.
    pub provenance: ProvenanceSummary,
    /// Fixity summary mirrored from the manifest's file declarations.
    pub fixity: FixitySummary,
    /// Rights metadata mirrored from the manifest.
    pub rights: RightsMetadata,
    /// Language metadata mirrored from the manifest.
    pub languages: Vec<String>,
}

/// One file entry in the local DGLAB interchange manifest scaffold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDglabInterchangeFileEntry {
    /// Path of the file within the source archive package.
    pub path: String,
    /// Role of this member in the source preservation package.
    pub role: PackageFileRole,
    /// IANA media type of the member.
    pub content_type: String,
    /// File size in bytes.
    pub byte_len: u64,
    /// SHA-256 fixity data from the source package manifest.
    pub checksum: FileChecksum,
    /// Act this file belongs to, if known by the source manifest.
    pub act_id: Option<uuid::Uuid>,
    /// Document this file belongs to, if known by the source manifest.
    pub document_id: Option<uuid::Uuid>,
}

impl From<&PackageFile> for LocalDglabInterchangeFileEntry {
    fn from(file: &PackageFile) -> Self {
        Self {
            path: file.path.clone(),
            role: file.role,
            content_type: file.content_type.clone(),
            byte_len: file.byte_len,
            checksum: file.checksum.clone(),
            act_id: file.act_id,
            document_id: file.document_id,
        }
    }
}

/// Deterministic file/fixity summary for the local DGLAB interchange scaffold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDglabInterchangeFileFixitySummary {
    /// Fixity algorithm used for every declared package member.
    pub algorithm: String,
    /// Number of declared content members.
    pub file_count: usize,
    /// Sum of declared content-member byte lengths.
    pub total_byte_len: u64,
}

/// Metadata-only local DGLAB/archive interchange scaffold.
///
/// This structure is built from an already validated [`PackageManifest`]. It is not written into
/// the ZIP package and does not claim official DGLAB interchange status, DGLAB approval,
/// legal-archive certification, or destructive disposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDglabInterchangeManifest {
    /// Machine-readable schema identifier.
    pub schema: String,
    /// Local interchange profile identifier.
    pub profile: String,
    /// Stable id of the source package.
    pub package_id: uuid::Uuid,
    /// Path of the source Chancela package manifest.
    pub source_manifest_path: String,
    /// Must remain false: this is not an official DGLAB interchange package.
    pub official_dglab_interchange: bool,
    /// Must remain false: this does not claim DGLAB certification.
    pub dglab_certification_claimed: bool,
    /// Must remain false: no external DGLAB approval is claimed.
    pub external_dglab_approval_obtained: bool,
    /// Must remain false: this does not certify a legal archive.
    pub legal_archive_certified: bool,
    /// Must remain false: this metadata scaffold records no destructive disposal.
    pub destructive_disposal_performed: bool,
    /// Producer/operator and source-system metadata mirrored from the source manifest.
    pub producer: ProducerMetadata,
    /// Internal package type mirrored from the source manifest.
    pub package_type: String,
    /// Internal package type version mirrored from the source manifest.
    pub package_version: String,
    /// Targeted preservation level mirrored from the source manifest.
    pub preservation_level: PreservationLevel,
    /// Local classification placeholders mirrored from the source manifest.
    pub local_classification: ClassificationMetadata,
    /// Rights metadata mirrored from the source manifest.
    pub rights: RightsMetadata,
    /// BCP-47 language tags mirrored from the source manifest.
    pub languages: Vec<String>,
    /// Retention/legal-hold instructions mirrored from the source manifest.
    pub retention: RetentionInstructions,
    /// File/fixity summary over the source manifest file declarations.
    pub file_fixity_summary: LocalDglabInterchangeFileFixitySummary,
    /// Source archive evidence index path when the source package declares one.
    pub evidence_index_path: Option<String>,
    /// Source manifest file entries, sorted by package path.
    pub files: Vec<LocalDglabInterchangeFileEntry>,
}

/// The manifest describing everything in an export package (DOC-20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Stable id of this package.
    pub package_id: uuid::Uuid,
    /// When the package was assembled.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    /// The entity the package belongs to.
    pub entity_id: uuid::Uuid,
    /// The book the packaged acts belong to.
    pub book_id: uuid::Uuid,
    /// The acts included in the package.
    pub act_ids: Vec<uuid::Uuid>,
    /// The documents included in the package, if known by the caller.
    pub document_ids: Vec<uuid::Uuid>,
    /// Packaged files with content types and fixity data.
    pub files: Vec<PackageFile>,
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
    /// Internal DGLAB-aligned preservation/interchange metadata.
    pub preservation_interchange: PreservationInterchangeMetadata,
}

/// Package container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchiveFormat {
    /// ZIP with `manifest.json` and deterministic member ordering.
    Zip,
}

/// A fully assembled export package ready to hand to an external archival/DMS system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPackage {
    /// Stable id of this package.
    pub id: uuid::Uuid,
    /// The manifest (checksums, provenance, rights, language, retention, preservation).
    pub manifest: PackageManifest,
    /// When the package was built.
    #[serde(with = "time::serde::rfc3339")]
    pub built_at: time::OffsetDateTime,
    /// Container format of `bytes`.
    pub format: ArchiveFormat,
    /// Serialized package bytes.
    pub bytes: Vec<u8>,
}

/// Explicit inputs for deterministic package assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageBuildInput {
    /// Stable id of this package.
    pub package_id: uuid::Uuid,
    /// Package creation time.
    pub created_at: time::OffsetDateTime,
    /// Entity id.
    pub entity_id: uuid::Uuid,
    /// Book id.
    pub book_id: uuid::Uuid,
    /// Act ids known before file-level metadata is processed.
    pub act_ids: Vec<uuid::Uuid>,
    /// Document ids known before file-level metadata is processed.
    pub document_ids: Vec<uuid::Uuid>,
    /// Producer/operator and source-system metadata.
    pub producer: ProducerMetadata,
    /// Internal package type.
    pub package_type: String,
    /// Internal package type version.
    pub package_version: String,
    /// Classification placeholders.
    pub classification: ClassificationMetadata,
    /// Provenance records.
    pub provenance: Vec<Provenance>,
    /// Rights metadata.
    pub rights: RightsMetadata,
    /// BCP-47 language tags.
    pub languages: Vec<String>,
    /// Retention instructions.
    pub retention: RetentionInstructions,
    /// Targeted preservation level.
    pub preservation_level: PreservationLevel,
    /// Optional trusted-client readability transfer. Defaults to metadata-only/no-key mode.
    pub readability: ReadabilityExport,
    /// Files to package.
    pub files: Vec<PackageFileInput>,
}

impl PackageBuildInput {
    /// Create package inputs with explicit package identity and creation time.
    pub fn new(
        package_id: uuid::Uuid,
        created_at: time::OffsetDateTime,
        entity_id: uuid::Uuid,
        book_id: uuid::Uuid,
    ) -> Self {
        Self {
            package_id,
            created_at,
            entity_id,
            book_id,
            act_ids: Vec::new(),
            document_ids: Vec::new(),
            producer: ProducerMetadata::default(),
            package_type: DEFAULT_PACKAGE_TYPE.to_owned(),
            package_version: DEFAULT_PACKAGE_VERSION.to_owned(),
            classification: ClassificationMetadata::default(),
            provenance: Vec::new(),
            rights: RightsMetadata::default(),
            languages: Vec::new(),
            retention: RetentionInstructions::default(),
            preservation_level: PreservationLevel::Managed,
            readability: ReadabilityExport::ManifestOnly,
            files: Vec::new(),
        }
    }
}

/// Errors from the archive subsystem.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArchiveError {
    /// A required piece of evidence (signed PDF, validation report, ...) was missing (DOC-03).
    #[error("required preservation artifact is missing: {0}")]
    MissingArtifact(String),
    /// A package member path is unsafe or otherwise invalid.
    #[error("invalid package path: {0}")]
    InvalidPath(String),
    /// The package contains duplicate member paths.
    #[error("duplicate package path: {0}")]
    DuplicatePath(String),
    /// The package manifest is malformed or inconsistent.
    #[error("invalid archive manifest: {0}")]
    InvalidManifest(String),
    /// Package bytes are malformed or contain untracked members.
    #[error("invalid archive package: {0}")]
    InvalidPackage(String),
    /// A packaged file digest does not match the manifest.
    #[error("checksum mismatch for {path}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        /// Path of the mismatching package member.
        path: String,
        /// Expected lower-case hex SHA-256 digest.
        expected: String,
        /// Actual lower-case hex SHA-256 digest.
        actual: String,
    },
}

/// Build a metadata-only package from a complete manifest.
///
/// Call [`build_archive_package`] when PDF/A bytes or signing/evidence report
/// bytes are available. This compatibility path can only emit `manifest.json`;
/// it rejects manifests that declare content files without corresponding bytes.
pub fn build_package(manifest: PackageManifest) -> Result<ExportPackage, ArchiveError> {
    validate_manifest(&manifest)?;
    if let Some(file) = manifest.files.first() {
        return Err(ArchiveError::MissingArtifact(file.path.clone()));
    }

    let bytes = write_package_zip(&manifest, &BTreeMap::new())?;
    Ok(ExportPackage {
        id: manifest.package_id,
        built_at: manifest.created_at,
        manifest,
        format: ArchiveFormat::Zip,
        bytes,
    })
}

/// Build a deterministic ZIP preservation package from explicit content inputs.
pub fn build_archive_package(mut input: PackageBuildInput) -> Result<ExportPackage, ArchiveError> {
    let readability_caveats = prepare_readability_export(&input.readability, &mut input.files)?;
    let mut member_bytes = BTreeMap::new();
    let mut files = Vec::with_capacity(input.files.len());
    let mut act_ids = input.act_ids;
    let mut document_ids = input.document_ids;
    let producer = input.producer;
    let package_type = input.package_type;
    let package_version = input.package_version;
    let classification = input.classification;
    let provenance = input.provenance;
    let rights = input.rights;
    let mut languages = input.languages;
    let retention = input.retention;
    let preservation_level = input.preservation_level;

    for file in input.files {
        validate_package_path(&file.path)?;
        if file.path == MANIFEST_PATH {
            return Err(ArchiveError::InvalidPath(file.path));
        }
        if file.content_type.trim().is_empty() {
            return Err(ArchiveError::InvalidManifest(format!(
                "content type is empty for {}",
                file.path
            )));
        }
        if member_bytes
            .insert(file.path.clone(), file.bytes.clone())
            .is_some()
        {
            return Err(ArchiveError::DuplicatePath(file.path));
        }

        if let Some(act_id) = file.act_id {
            act_ids.push(act_id);
        }
        if let Some(document_id) = file.document_id {
            document_ids.push(document_id);
        }

        files.push(PackageFile {
            path: file.path,
            role: file.role,
            content_type: file.content_type,
            byte_len: file.bytes.len() as u64,
            checksum: FileChecksum {
                algorithm: SHA256.to_owned(),
                hex_digest: sha256_hex(&file.bytes),
            },
            act_id: file.act_id,
            document_id: file.document_id,
        });
    }

    files.sort_by(|left, right| left.path.cmp(&right.path));
    sort_dedup(&mut act_ids);
    sort_dedup(&mut document_ids);
    sort_dedup_strings(&mut languages);

    let preservation_interchange =
        preservation_interchange_metadata(PreservationInterchangeInput {
            producer,
            package_type,
            package_version,
            classification,
            preservation_level,
            retention: retention.clone(),
            provenance: &provenance,
            files: &files,
            rights: rights.clone(),
            languages: languages.clone(),
            readability_caveats,
        });

    let manifest = PackageManifest {
        package_id: input.package_id,
        created_at: input.created_at,
        entity_id: input.entity_id,
        book_id: input.book_id,
        act_ids,
        document_ids,
        files,
        provenance,
        rights,
        languages,
        retention,
        preservation_level,
        preservation_interchange,
    };
    validate_manifest(&manifest)?;

    let bytes = write_package_zip(&manifest, &member_bytes)?;
    Ok(ExportPackage {
        id: manifest.package_id,
        built_at: manifest.created_at,
        manifest,
        format: ArchiveFormat::Zip,
        bytes,
    })
}

/// Read `manifest.json` from a ZIP package without validating file fixity.
pub fn read_package_manifest(package_bytes: &[u8]) -> Result<PackageManifest, ArchiveError> {
    let members = read_zip_members(package_bytes)?;
    let manifest_bytes = members
        .get(MANIFEST_PATH)
        .ok_or_else(|| ArchiveError::InvalidPackage("missing manifest.json".to_owned()))?;
    serde_json::from_slice(manifest_bytes)
        .map_err(|e| ArchiveError::InvalidManifest(format!("manifest.json is not valid JSON: {e}")))
}

/// Validate manifest structure and member SHA-256 checksums for a ZIP package.
pub fn validate_package(package_bytes: &[u8]) -> Result<PackageManifest, ArchiveError> {
    let members = read_zip_members(package_bytes)?;
    let manifest_bytes = members
        .get(MANIFEST_PATH)
        .ok_or_else(|| ArchiveError::InvalidPackage("missing manifest.json".to_owned()))?;
    let manifest: PackageManifest = serde_json::from_slice(manifest_bytes).map_err(|e| {
        ArchiveError::InvalidManifest(format!("manifest.json is not valid JSON: {e}"))
    })?;
    validate_manifest(&manifest)?;

    let expected_paths: BTreeSet<_> = manifest
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    for name in members.keys() {
        if name != MANIFEST_PATH && !expected_paths.contains(name.as_str()) {
            return Err(ArchiveError::InvalidPackage(format!(
                "untracked member {name}"
            )));
        }
    }

    for file in &manifest.files {
        let bytes = members
            .get(&file.path)
            .ok_or_else(|| ArchiveError::MissingArtifact(file.path.clone()))?;
        let actual = sha256_hex(bytes);
        if bytes.len() as u64 != file.byte_len {
            return Err(ArchiveError::InvalidPackage(format!(
                "byte length mismatch for {}: expected {}, got {}",
                file.path,
                file.byte_len,
                bytes.len()
            )));
        }
        if actual != file.checksum.hex_digest {
            return Err(ArchiveError::ChecksumMismatch {
                path: file.path.clone(),
                expected: file.checksum.hex_digest.clone(),
                actual,
            });
        }
    }

    validate_readability_member_bytes(&manifest, &members)?;

    Ok(manifest)
}

/// Build a metadata-only local DGLAB/archive interchange scaffold.
///
/// The scaffold is derived from an already valid [`PackageManifest`] and does not create or alter
/// ZIP/package bytes.
pub fn build_local_dglab_interchange_manifest(
    source: &PackageManifest,
) -> Result<LocalDglabInterchangeManifest, ArchiveError> {
    validate_manifest(source)?;

    let files = local_dglab_file_entries(&source.files);
    let manifest = LocalDglabInterchangeManifest {
        schema: LOCAL_DGLAB_INTERCHANGE_MANIFEST_SCHEMA.to_owned(),
        profile: LOCAL_DGLAB_INTERCHANGE_MANIFEST_PROFILE.to_owned(),
        package_id: source.package_id,
        source_manifest_path: MANIFEST_PATH.to_owned(),
        official_dglab_interchange: false,
        dglab_certification_claimed: false,
        external_dglab_approval_obtained: false,
        legal_archive_certified: false,
        destructive_disposal_performed: false,
        producer: source.preservation_interchange.producer.clone(),
        package_type: source.preservation_interchange.package_type.clone(),
        package_version: source.preservation_interchange.package_version.clone(),
        preservation_level: source.preservation_level,
        local_classification: source.preservation_interchange.classification.clone(),
        rights: source.rights.clone(),
        languages: source.languages.clone(),
        retention: source.retention.clone(),
        file_fixity_summary: LocalDglabInterchangeFileFixitySummary {
            algorithm: SHA256.to_owned(),
            file_count: files.len(),
            total_byte_len: files.iter().map(|file| file.byte_len).sum(),
        },
        evidence_index_path: local_dglab_evidence_index_path(source),
        files,
    };
    validate_local_dglab_interchange_manifest(&manifest, source)?;
    Ok(manifest)
}

/// Validate a local DGLAB/archive interchange scaffold against its source manifest.
pub fn validate_local_dglab_interchange_manifest(
    manifest: &LocalDglabInterchangeManifest,
    source: &PackageManifest,
) -> Result<(), ArchiveError> {
    validate_manifest(source)?;
    validate_required_text("local_dglab_interchange.schema", &manifest.schema)?;
    validate_required_text("local_dglab_interchange.profile", &manifest.profile)?;
    if manifest.schema != LOCAL_DGLAB_INTERCHANGE_MANIFEST_SCHEMA {
        return Err(ArchiveError::InvalidManifest(format!(
            "local_dglab_interchange.schema must be {LOCAL_DGLAB_INTERCHANGE_MANIFEST_SCHEMA}"
        )));
    }
    if manifest.profile != LOCAL_DGLAB_INTERCHANGE_MANIFEST_PROFILE {
        return Err(ArchiveError::InvalidManifest(format!(
            "local_dglab_interchange.profile must be {LOCAL_DGLAB_INTERCHANGE_MANIFEST_PROFILE}"
        )));
    }
    validate_package_path(&manifest.source_manifest_path)?;
    if manifest.source_manifest_path != MANIFEST_PATH {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.source_manifest_path must be manifest.json".to_owned(),
        ));
    }
    validate_false_claim_flag(
        "local_dglab_interchange.official_dglab_interchange",
        manifest.official_dglab_interchange,
    )?;
    validate_false_claim_flag(
        "local_dglab_interchange.dglab_certification_claimed",
        manifest.dglab_certification_claimed,
    )?;
    validate_false_claim_flag(
        "local_dglab_interchange.external_dglab_approval_obtained",
        manifest.external_dglab_approval_obtained,
    )?;
    validate_false_claim_flag(
        "local_dglab_interchange.legal_archive_certified",
        manifest.legal_archive_certified,
    )?;
    validate_false_claim_flag(
        "local_dglab_interchange.destructive_disposal_performed",
        manifest.destructive_disposal_performed,
    )?;
    validate_required_text(
        "local_dglab_interchange.producer.name",
        &manifest.producer.name,
    )?;
    validate_required_text(
        "local_dglab_interchange.producer.system",
        &manifest.producer.system,
    )?;
    validate_required_text(
        "local_dglab_interchange.package_type",
        &manifest.package_type,
    )?;
    validate_required_text(
        "local_dglab_interchange.package_version",
        &manifest.package_version,
    )?;
    validate_classification(&manifest.local_classification)?;
    validate_rights(&manifest.rights)?;
    validate_languages(&manifest.languages)?;
    validate_retention(&manifest.retention)?;
    validate_required_text(
        "local_dglab_interchange.file_fixity_summary.algorithm",
        &manifest.file_fixity_summary.algorithm,
    )?;

    if manifest.package_id != source.package_id {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.package_id must match source package_id".to_owned(),
        ));
    }
    if manifest.producer != source.preservation_interchange.producer {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.producer must match source preservation_interchange"
                .to_owned(),
        ));
    }
    if manifest.package_type != source.preservation_interchange.package_type {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.package_type must match source preservation_interchange"
                .to_owned(),
        ));
    }
    if manifest.package_version != source.preservation_interchange.package_version {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.package_version must match source preservation_interchange"
                .to_owned(),
        ));
    }
    if manifest.preservation_level != source.preservation_level {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.preservation_level must match source preservation_level"
                .to_owned(),
        ));
    }
    if manifest.local_classification != source.preservation_interchange.classification {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.local_classification must match source preservation_interchange"
                .to_owned(),
        ));
    }
    if manifest.rights != source.rights {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.rights must match source rights".to_owned(),
        ));
    }
    if manifest.languages != source.languages {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.languages must match source languages".to_owned(),
        ));
    }
    if manifest.retention != source.retention {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.retention must match source retention".to_owned(),
        ));
    }
    if manifest.file_fixity_summary.algorithm != SHA256 {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.file_fixity_summary.algorithm must be sha256".to_owned(),
        ));
    }
    if manifest.file_fixity_summary.file_count != source.files.len() {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.file_fixity_summary.file_count must match source files"
                .to_owned(),
        ));
    }
    let total_byte_len: u64 = source.files.iter().map(|file| file.byte_len).sum();
    if manifest.file_fixity_summary.total_byte_len != total_byte_len {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.file_fixity_summary.total_byte_len must match source files"
                .to_owned(),
        ));
    }
    if manifest.file_fixity_summary.file_count != manifest.files.len() {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.file_fixity_summary.file_count must match file entries"
                .to_owned(),
        ));
    }
    let entry_total_byte_len: u64 = manifest.files.iter().map(|file| file.byte_len).sum();
    if manifest.file_fixity_summary.total_byte_len != entry_total_byte_len {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.file_fixity_summary.total_byte_len must match file entries"
                .to_owned(),
        ));
    }
    if let Some(path) = &manifest.evidence_index_path {
        validate_package_path(path)?;
    }
    if manifest.evidence_index_path != local_dglab_evidence_index_path(source) {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.evidence_index_path must match source files".to_owned(),
        ));
    }

    validate_local_dglab_file_entries(&manifest.files)?;
    let expected_files = local_dglab_file_entries(&source.files);
    if manifest.files != expected_files {
        return Err(ArchiveError::InvalidManifest(
            "local_dglab_interchange.files must match source manifest files".to_owned(),
        ));
    }

    Ok(())
}

/// Validate manifest-only invariants.
pub fn validate_manifest(manifest: &PackageManifest) -> Result<(), ArchiveError> {
    let mut paths = BTreeSet::new();
    let mut previous_path: Option<&str> = None;
    for file in &manifest.files {
        validate_package_path(&file.path)?;
        if file.path == MANIFEST_PATH {
            return Err(ArchiveError::InvalidPath(file.path.clone()));
        }
        if let Some(previous) = previous_path
            && previous > file.path.as_str()
        {
            return Err(ArchiveError::InvalidManifest(
                "files must be sorted by package path".to_owned(),
            ));
        }
        previous_path = Some(file.path.as_str());
        if !paths.insert(file.path.as_str()) {
            return Err(ArchiveError::DuplicatePath(file.path.clone()));
        }
        if file.content_type.trim().is_empty() {
            return Err(ArchiveError::InvalidManifest(format!(
                "content type is empty for {}",
                file.path
            )));
        }
        if file.checksum.algorithm != SHA256 {
            return Err(ArchiveError::InvalidManifest(format!(
                "unsupported checksum algorithm {} for {}",
                file.checksum.algorithm, file.path
            )));
        }
        if !is_sha256_hex(&file.checksum.hex_digest) {
            return Err(ArchiveError::InvalidManifest(format!(
                "invalid sha256 digest for {}",
                file.path
            )));
        }
        if let Some(act_id) = file.act_id
            && !manifest.act_ids.contains(&act_id)
        {
            return Err(ArchiveError::InvalidManifest(format!(
                "file {} references act id {} not listed in act_ids",
                file.path, act_id
            )));
        }
        if let Some(document_id) = file.document_id
            && !manifest.document_ids.contains(&document_id)
        {
            return Err(ArchiveError::InvalidManifest(format!(
                "file {} references document id {} not listed in document_ids",
                file.path, document_id
            )));
        }
    }
    validate_sorted_unique_ids("act_ids", &manifest.act_ids)?;
    validate_sorted_unique_ids("document_ids", &manifest.document_ids)?;
    validate_provenance(&manifest.provenance)?;
    validate_rights(&manifest.rights)?;
    validate_languages(&manifest.languages)?;
    validate_retention(&manifest.retention)?;
    validate_interchange_metadata(manifest)?;
    Ok(())
}

struct PreservationInterchangeInput<'a> {
    producer: ProducerMetadata,
    package_type: String,
    package_version: String,
    classification: ClassificationMetadata,
    preservation_level: PreservationLevel,
    retention: RetentionInstructions,
    provenance: &'a [Provenance],
    files: &'a [PackageFile],
    rights: RightsMetadata,
    languages: Vec<String>,
    readability_caveats: ReadabilityCaveatMetadata,
}

fn preservation_interchange_metadata(
    input: PreservationInterchangeInput<'_>,
) -> PreservationInterchangeMetadata {
    let producer_name = input.producer.name.trim().to_owned();
    let producer_system = input.producer.system.trim().to_owned();
    PreservationInterchangeMetadata {
        profile: PRESERVATION_INTERCHANGE_PROFILE.to_owned(),
        official_dglab_interchange: false,
        dglab_certification_claimed: false,
        readability_caveats: input.readability_caveats,
        producer: ProducerMetadata {
            name: producer_name,
            system: producer_system.clone(),
        },
        package_type: input.package_type.trim().to_owned(),
        package_version: input.package_version.trim().to_owned(),
        preservation_level: input.preservation_level,
        classification: input.classification,
        retention: input.retention,
        provenance: ProvenanceSummary {
            source_system: producer_system,
            record_count: input.provenance.len(),
            captured_record_count: input
                .provenance
                .iter()
                .filter(|record| record.captured_at.is_some())
                .count(),
        },
        fixity: FixitySummary {
            algorithm: SHA256.to_owned(),
            manifest_path: MANIFEST_PATH.to_owned(),
            file_count: input.files.len(),
            total_byte_len: input.files.iter().map(|file| file.byte_len).sum(),
        },
        rights: input.rights,
        languages: input.languages,
    }
}

fn prepare_readability_export(
    export: &ReadabilityExport,
    files: &mut Vec<PackageFileInput>,
) -> Result<ReadabilityCaveatMetadata, ArchiveError> {
    let explicit = |source_repository_id: uuid::Uuid,
                    mode: LegalArchiveReadabilityMode,
                    decryption_material_included: bool|
     -> Result<ReadabilityCaveatMetadata, ArchiveError> {
        if source_repository_id.is_nil() {
            return Err(ArchiveError::InvalidManifest(
                "readability source_repository_id must not be nil".to_owned(),
            ));
        }
        Ok(ReadabilityCaveatMetadata {
            legal_archive_readability_mode: mode,
            decryption_material_included,
            external_import_verified: false,
            legal_archive_certified: false,
            zk_repository_mode: true,
            zk_removes_gdpr_obligations: false,
            source_repository_id: Some(source_repository_id),
            documentation_path: Some(READABILITY_DOCUMENTATION_PATH.to_owned()),
            decryption_material_path: decryption_material_included
                .then(|| READABILITY_KEY_PACKAGE_PATH.to_owned()),
        })
    };

    match export {
        ReadabilityExport::ManifestOnly => Ok(ReadabilityCaveatMetadata::default()),
        ReadabilityExport::ClientDecryptedTransfer {
            source_repository_id,
        } => {
            files.push(PackageFileInput::new(
                READABILITY_DOCUMENTATION_PATH,
                PackageFileRole::ReadabilityDocumentation,
                "text/markdown; charset=utf-8",
                readability_documentation(
                    *source_repository_id,
                    LegalArchiveReadabilityMode::ClientDecryptedTransfer,
                    None,
                )
                .into_bytes(),
            ));
            explicit(
                *source_repository_id,
                LegalArchiveReadabilityMode::ClientDecryptedTransfer,
                false,
            )
        }
        ReadabilityExport::EncryptedTransferWithPortableKeyPackage {
            source_repository_id,
            portable_key_package_jwe,
            recipient_instructions,
        } => {
            validate_compact_jwe(portable_key_package_jwe)?;
            validate_readability_instructions(recipient_instructions)?;
            files.push(PackageFileInput::new(
                READABILITY_DOCUMENTATION_PATH,
                PackageFileRole::ReadabilityDocumentation,
                "text/markdown; charset=utf-8",
                readability_documentation(
                    *source_repository_id,
                    LegalArchiveReadabilityMode::EncryptedTransferWithPortableKeyPackage,
                    Some(recipient_instructions),
                )
                .into_bytes(),
            ));
            files.push(PackageFileInput::new(
                READABILITY_KEY_PACKAGE_PATH,
                PackageFileRole::EncryptedDecryptionMaterial,
                "application/jose",
                portable_key_package_jwe.as_bytes().to_vec(),
            ));
            explicit(
                *source_repository_id,
                LegalArchiveReadabilityMode::EncryptedTransferWithPortableKeyPackage,
                true,
            )
        }
    }
}

fn readability_documentation(
    repository_id: uuid::Uuid,
    mode: LegalArchiveReadabilityMode,
    recipient_instructions: Option<&str>,
) -> String {
    let mode = match mode {
        LegalArchiveReadabilityMode::ManifestOnly => "manifest-only",
        LegalArchiveReadabilityMode::ClientDecryptedTransfer => "client-decrypted transfer",
        LegalArchiveReadabilityMode::EncryptedTransferWithPortableKeyPackage => {
            "encrypted transfer with a portable encrypted key package"
        }
    };
    let instructions = recipient_instructions
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("No encrypted key package is included; the trusted client decrypted the archive before transfer.");
    format!(
        "# Chancela legal archive readability transfer\n\nSource repository: `{repository_id}`\n\nTransfer mode: {mode}.\n\n{instructions}\n\nThe recipient must verify every SHA-256 digest in `manifest.json` before import. This package does not certify a legal archive or prove an external import. Zero-knowledge encryption reduces exposure but does not remove GDPR obligations.\n"
    )
}

fn validate_readability_instructions(value: &str) -> Result<(), ArchiveError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_READABILITY_INSTRUCTIONS_BYTES
        || trimmed.contains('\0')
    {
        return Err(ArchiveError::InvalidManifest(
            "readability recipient_instructions must be non-empty and bounded".to_owned(),
        ));
    }
    Ok(())
}

fn validate_compact_jwe(value: &str) -> Result<(), ArchiveError> {
    if value.is_empty()
        || value.len() > MAX_READABILITY_JWE_BYTES
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ArchiveError::InvalidManifest(
            "portable key package must be a bounded compact JWE".to_owned(),
        ));
    }
    let segments: Vec<_> = value.split('.').collect();
    if segments.len() != 5
        || segments.iter().any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
    {
        return Err(ArchiveError::InvalidManifest(
            "portable key package must have five non-empty base64url JWE segments".to_owned(),
        ));
    }
    Ok(())
}

fn local_dglab_file_entries(files: &[PackageFile]) -> Vec<LocalDglabInterchangeFileEntry> {
    files
        .iter()
        .map(LocalDglabInterchangeFileEntry::from)
        .collect()
}

fn local_dglab_evidence_index_path(source: &PackageManifest) -> Option<String> {
    source
        .files
        .iter()
        .any(|file| file.path == EVIDENCE_INDEX_PATH)
        .then(|| EVIDENCE_INDEX_PATH.to_owned())
}

fn validate_false_claim_flag(label: &str, value: bool) -> Result<(), ArchiveError> {
    if value {
        return Err(ArchiveError::InvalidManifest(format!(
            "{label} must be false"
        )));
    }
    Ok(())
}

fn validate_readability_caveats(
    caveats: &ReadabilityCaveatMetadata,
    files: &[PackageFile],
) -> Result<(), ArchiveError> {
    validate_false_claim_flag(
        "preservation_interchange.readability_caveats.external_import_verified",
        caveats.external_import_verified,
    )?;
    validate_false_claim_flag(
        "preservation_interchange.readability_caveats.legal_archive_certified",
        caveats.legal_archive_certified,
    )?;
    validate_false_claim_flag(
        "preservation_interchange.readability_caveats.zk_removes_gdpr_obligations",
        caveats.zk_removes_gdpr_obligations,
    )?;

    let reserved_file = |path: &str| files.iter().find(|file| file.path == path);
    let no_explicit_metadata = || {
        caveats.source_repository_id.is_none()
            && caveats.documentation_path.is_none()
            && caveats.decryption_material_path.is_none()
    };
    match caveats.legal_archive_readability_mode {
        LegalArchiveReadabilityMode::ManifestOnly => {
            if caveats.decryption_material_included {
                return Err(ArchiveError::InvalidManifest(
                    "preservation_interchange.readability_caveats.decryption_material_included must be false in manifest_only mode"
                        .to_owned(),
                ));
            }
            if caveats.zk_repository_mode {
                return Err(ArchiveError::InvalidManifest(
                    "preservation_interchange.readability_caveats.zk_repository_mode must be false in manifest_only mode"
                        .to_owned(),
                ));
            }
            if !no_explicit_metadata()
                || reserved_file(READABILITY_DOCUMENTATION_PATH).is_some()
                || reserved_file(READABILITY_KEY_PACKAGE_PATH).is_some()
            {
                return Err(ArchiveError::InvalidManifest(
                    "manifest_only readability cannot declare ZK transfer members or material"
                        .to_owned(),
                ));
            }
            Ok(())
        }
        LegalArchiveReadabilityMode::ClientDecryptedTransfer => {
            if caveats.decryption_material_included
                || !caveats.zk_repository_mode
                || caveats.source_repository_id.is_none()
                || caveats.documentation_path.as_deref() != Some(READABILITY_DOCUMENTATION_PATH)
                || caveats.decryption_material_path.is_some()
                || reserved_file(READABILITY_KEY_PACKAGE_PATH).is_some()
            {
                return Err(ArchiveError::InvalidManifest(
                    "client_decrypted_transfer readability metadata is inconsistent".to_owned(),
                ));
            }
            validate_readability_file(
                reserved_file(READABILITY_DOCUMENTATION_PATH),
                PackageFileRole::ReadabilityDocumentation,
                "readability documentation",
            )
        }
        LegalArchiveReadabilityMode::EncryptedTransferWithPortableKeyPackage => {
            if !caveats.decryption_material_included
                || !caveats.zk_repository_mode
                || caveats.source_repository_id.is_none()
                || caveats.documentation_path.as_deref() != Some(READABILITY_DOCUMENTATION_PATH)
                || caveats.decryption_material_path.as_deref() != Some(READABILITY_KEY_PACKAGE_PATH)
            {
                return Err(ArchiveError::InvalidManifest(
                    "encrypted readability transfer metadata is inconsistent".to_owned(),
                ));
            }
            validate_readability_file(
                reserved_file(READABILITY_DOCUMENTATION_PATH),
                PackageFileRole::ReadabilityDocumentation,
                "readability documentation",
            )?;
            validate_readability_file(
                reserved_file(READABILITY_KEY_PACKAGE_PATH),
                PackageFileRole::EncryptedDecryptionMaterial,
                "encrypted decryption material",
            )
        }
    }
}

fn validate_readability_file(
    file: Option<&PackageFile>,
    role: PackageFileRole,
    label: &str,
) -> Result<(), ArchiveError> {
    let file = file.ok_or_else(|| ArchiveError::MissingArtifact(label.to_owned()))?;
    if file.role != role {
        return Err(ArchiveError::InvalidManifest(format!(
            "{label} has the wrong package role"
        )));
    }
    Ok(())
}

fn validate_readability_member_bytes(
    manifest: &PackageManifest,
    members: &BTreeMap<String, Vec<u8>>,
) -> Result<(), ArchiveError> {
    let caveats = &manifest.preservation_interchange.readability_caveats;
    match caveats.legal_archive_readability_mode {
        LegalArchiveReadabilityMode::ManifestOnly => Ok(()),
        LegalArchiveReadabilityMode::ClientDecryptedTransfer
        | LegalArchiveReadabilityMode::EncryptedTransferWithPortableKeyPackage => {
            let documentation = members.get(READABILITY_DOCUMENTATION_PATH).ok_or_else(|| {
                ArchiveError::MissingArtifact(READABILITY_DOCUMENTATION_PATH.to_owned())
            })?;
            let documentation = std::str::from_utf8(documentation).map_err(|_| {
                ArchiveError::InvalidPackage(
                    "readability documentation must be valid UTF-8".to_owned(),
                )
            })?;
            if !documentation.contains(
                "Zero-knowledge encryption reduces exposure but does not remove GDPR obligations.",
            ) || !documentation.contains("does not certify a legal archive")
            {
                return Err(ArchiveError::InvalidPackage(
                    "readability documentation is missing mandatory no-overclaim caveats"
                        .to_owned(),
                ));
            }
            if caveats.legal_archive_readability_mode
                == LegalArchiveReadabilityMode::EncryptedTransferWithPortableKeyPackage
            {
                let jwe = members.get(READABILITY_KEY_PACKAGE_PATH).ok_or_else(|| {
                    ArchiveError::MissingArtifact(READABILITY_KEY_PACKAGE_PATH.to_owned())
                })?;
                let jwe = std::str::from_utf8(jwe).map_err(|_| {
                    ArchiveError::InvalidPackage(
                        "portable key package must be UTF-8 compact JWE".to_owned(),
                    )
                })?;
                validate_compact_jwe(jwe)?;
            }
            Ok(())
        }
    }
}

fn validate_local_dglab_file_entries(
    files: &[LocalDglabInterchangeFileEntry],
) -> Result<(), ArchiveError> {
    let mut paths = BTreeSet::new();
    let mut previous_path: Option<&str> = None;
    for file in files {
        validate_package_path(&file.path)?;
        if file.path == MANIFEST_PATH {
            return Err(ArchiveError::InvalidPath(file.path.clone()));
        }
        if let Some(previous) = previous_path
            && previous > file.path.as_str()
        {
            return Err(ArchiveError::InvalidManifest(
                "local_dglab_interchange.files must be sorted by package path".to_owned(),
            ));
        }
        previous_path = Some(file.path.as_str());
        if !paths.insert(file.path.as_str()) {
            return Err(ArchiveError::DuplicatePath(file.path.clone()));
        }
        if file.content_type.trim().is_empty() {
            return Err(ArchiveError::InvalidManifest(format!(
                "content type is empty for local_dglab_interchange file {}",
                file.path
            )));
        }
        if file.checksum.algorithm != SHA256 {
            return Err(ArchiveError::InvalidManifest(format!(
                "unsupported local_dglab_interchange checksum algorithm {} for {}",
                file.checksum.algorithm, file.path
            )));
        }
        if !is_sha256_hex(&file.checksum.hex_digest) {
            return Err(ArchiveError::InvalidManifest(format!(
                "invalid local_dglab_interchange sha256 digest for {}",
                file.path
            )));
        }
    }
    Ok(())
}

fn validate_interchange_metadata(manifest: &PackageManifest) -> Result<(), ArchiveError> {
    let metadata = &manifest.preservation_interchange;
    if metadata.profile != PRESERVATION_INTERCHANGE_PROFILE {
        return Err(ArchiveError::InvalidManifest(format!(
            "preservation_interchange.profile must be {PRESERVATION_INTERCHANGE_PROFILE}"
        )));
    }
    if metadata.official_dglab_interchange {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.official_dglab_interchange must be false".to_owned(),
        ));
    }
    if metadata.dglab_certification_claimed {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.dglab_certification_claimed must be false".to_owned(),
        ));
    }
    validate_readability_caveats(&metadata.readability_caveats, &manifest.files)?;
    validate_required_text(
        "preservation_interchange.producer.name",
        &metadata.producer.name,
    )?;
    validate_required_text(
        "preservation_interchange.producer.system",
        &metadata.producer.system,
    )?;
    validate_required_text(
        "preservation_interchange.package_type",
        &metadata.package_type,
    )?;
    validate_required_text(
        "preservation_interchange.package_version",
        &metadata.package_version,
    )?;
    validate_classification(&metadata.classification)?;
    if metadata.preservation_level != manifest.preservation_level {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.preservation_level must match preservation_level".to_owned(),
        ));
    }
    if metadata.retention != manifest.retention {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.retention must match retention".to_owned(),
        ));
    }
    if metadata.rights != manifest.rights {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.rights must match rights".to_owned(),
        ));
    }
    if metadata.languages != manifest.languages {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.languages must match languages".to_owned(),
        ));
    }
    validate_languages(&metadata.languages)?;
    validate_required_text(
        "preservation_interchange.provenance.source_system",
        &metadata.provenance.source_system,
    )?;
    if metadata.provenance.record_count != manifest.provenance.len() {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.provenance.record_count must match provenance length"
                .to_owned(),
        ));
    }
    let captured_record_count = manifest
        .provenance
        .iter()
        .filter(|record| record.captured_at.is_some())
        .count();
    if metadata.provenance.captured_record_count != captured_record_count {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.provenance.captured_record_count must match provenance"
                .to_owned(),
        ));
    }
    if metadata.fixity.algorithm != SHA256 {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.fixity.algorithm must be sha256".to_owned(),
        ));
    }
    if metadata.fixity.manifest_path != MANIFEST_PATH {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.fixity.manifest_path must be manifest.json".to_owned(),
        ));
    }
    if metadata.fixity.file_count != manifest.files.len() {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.fixity.file_count must match files length".to_owned(),
        ));
    }
    let total_byte_len: u64 = manifest.files.iter().map(|file| file.byte_len).sum();
    if metadata.fixity.total_byte_len != total_byte_len {
        return Err(ArchiveError::InvalidManifest(
            "preservation_interchange.fixity.total_byte_len must match files".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sorted_unique_ids(label: &str, values: &[uuid::Uuid]) -> Result<(), ArchiveError> {
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(ArchiveError::InvalidManifest(format!(
                "duplicate id in {label}: {}",
                pair[0]
            )));
        }
        if pair[0] > pair[1] {
            return Err(ArchiveError::InvalidManifest(format!(
                "{label} must be sorted for deterministic serialization"
            )));
        }
    }
    Ok(())
}

fn validate_provenance(provenance: &[Provenance]) -> Result<(), ArchiveError> {
    for record in provenance {
        validate_required_text("provenance.reference", &record.reference)?;
    }
    Ok(())
}

fn validate_rights(rights: &RightsMetadata) -> Result<(), ArchiveError> {
    validate_optional_text("rights.holder", rights.holder.as_deref())?;
    validate_optional_text("rights.license", rights.license.as_deref())?;
    validate_optional_text("rights.access_note", rights.access_note.as_deref())
}

fn validate_languages(languages: &[String]) -> Result<(), ArchiveError> {
    if languages.is_empty() {
        return Err(ArchiveError::InvalidManifest(
            "languages must include at least one BCP-47 tag".to_owned(),
        ));
    }
    for language in languages {
        validate_required_text("languages", language)?;
    }
    for pair in languages.windows(2) {
        if pair[0] == pair[1] {
            return Err(ArchiveError::InvalidManifest(format!(
                "duplicate language tag {}",
                pair[0]
            )));
        }
        if pair[0] > pair[1] {
            return Err(ArchiveError::InvalidManifest(
                "languages must be sorted for deterministic serialization".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_retention(retention: &RetentionInstructions) -> Result<(), ArchiveError> {
    validate_optional_text("retention.schedule_id", retention.schedule_id.as_deref())
}

fn validate_classification(classification: &ClassificationMetadata) -> Result<(), ArchiveError> {
    validate_optional_text("classification.scheme", classification.scheme.as_deref())?;
    validate_optional_text("classification.code", classification.code.as_deref())?;
    validate_optional_text("classification.title", classification.title.as_deref())?;
    validate_optional_text(
        "classification.sensitivity",
        classification.sensitivity.as_deref(),
    )
}

fn validate_required_text(label: &str, value: &str) -> Result<(), ArchiveError> {
    if value.trim().is_empty() {
        return Err(ArchiveError::InvalidManifest(format!(
            "{label} must not be blank"
        )));
    }
    Ok(())
}

fn validate_optional_text(label: &str, value: Option<&str>) -> Result<(), ArchiveError> {
    if let Some(value) = value {
        validate_required_text(label, value)?;
    }
    Ok(())
}

fn write_package_zip(
    manifest: &PackageManifest,
    member_bytes: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, ArchiveError> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(zip::DateTime::default());

    zip.start_file(MANIFEST_PATH, opts).map_err(zip_error)?;
    let manifest_bytes = serde_json::to_vec_pretty(manifest).map_err(|e| {
        ArchiveError::InvalidManifest(format!("manifest serialization failed: {e}"))
    })?;
    zip.write_all(&manifest_bytes)
        .map_err(|e| ArchiveError::InvalidPackage(format!("failed to write manifest: {e}")))?;

    for file in &manifest.files {
        let bytes = member_bytes
            .get(&file.path)
            .ok_or_else(|| ArchiveError::MissingArtifact(file.path.clone()))?;
        zip.start_file(file.path.as_str(), opts)
            .map_err(zip_error)?;
        zip.write_all(bytes).map_err(|e| {
            ArchiveError::InvalidPackage(format!("failed to write {}: {e}", file.path))
        })?;
    }

    zip.finish()
        .map(|cursor| cursor.into_inner())
        .map_err(zip_error)
}

fn read_zip_members(package_bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ArchiveError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(package_bytes))
        .map_err(|e| ArchiveError::InvalidPackage(format!("not a readable zip: {e}")))?;
    let mut members = BTreeMap::new();

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|e| ArchiveError::InvalidPackage(format!("cannot read zip member: {e}")))?;
        let name = file.name().to_owned();
        validate_package_path(&name)?;
        if members.contains_key(&name) {
            return Err(ArchiveError::DuplicatePath(name));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| {
            ArchiveError::InvalidPackage(format!("failed to read zip member {name}: {e}"))
        })?;
        members.insert(name, bytes);
    }

    Ok(members)
}

fn validate_package_path(path: &str) -> Result<(), ArchiveError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ArchiveError::InvalidPath(path.to_owned()));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sort_dedup(values: &mut Vec<uuid::Uuid>) {
    values.sort_unstable();
    values.dedup();
}

fn sort_dedup_strings(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        *value = value.trim().to_owned();
    }
    values.sort_unstable();
    values.dedup();
}

fn zip_error(error: zip::result::ZipError) -> ArchiveError {
    ArchiveError::InvalidPackage(format!("zip error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    fn sample_created_at() -> time::OffsetDateTime {
        time::macros::datetime!(2026-02-03 04:05:06 UTC)
    }

    fn sample_manifest() -> PackageManifest {
        let files = vec![];
        let provenance = vec![Provenance {
            source: ProvenanceSource::SealedAct,
            reference: "act:4".into(),
            captured_at: None,
        }];
        let rights = RightsMetadata::default();
        let languages = vec!["pt-PT".into()];
        let retention = RetentionInstructions::default();
        let preservation_level = PreservationLevel::Managed;
        let preservation_interchange =
            preservation_interchange_metadata(PreservationInterchangeInput {
                producer: ProducerMetadata::default(),
                package_type: DEFAULT_PACKAGE_TYPE.to_owned(),
                package_version: DEFAULT_PACKAGE_VERSION.to_owned(),
                classification: ClassificationMetadata::default(),
                preservation_level,
                retention: retention.clone(),
                provenance: &provenance,
                files: &files,
                rights: rights.clone(),
                languages: languages.clone(),
                readability_caveats: ReadabilityCaveatMetadata::default(),
            });
        PackageManifest {
            package_id: id(1),
            created_at: sample_created_at(),
            entity_id: id(2),
            book_id: id(3),
            act_ids: vec![id(4)],
            document_ids: vec![id(5)],
            files,
            provenance,
            rights,
            languages,
            retention,
            preservation_level,
            preservation_interchange,
        }
    }

    fn sample_input() -> PackageBuildInput {
        let act_id = id(4);
        let document_id = id(5);
        let mut input = PackageBuildInput::new(id(1), sample_created_at(), id(2), id(3));
        input.act_ids = vec![act_id];
        input.provenance = vec![Provenance {
            source: ProvenanceSource::SealedAct,
            reference: act_id.to_string(),
            captured_at: Some(sample_created_at()),
        }];
        input.rights = RightsMetadata {
            holder: Some("Chancela".into()),
            license: None,
            access_note: Some("internal".into()),
        };
        input.languages = vec!["pt-PT".into()];
        input.retention = RetentionInstructions {
            schedule_id: Some("default".into()),
            review_after: None,
            legal_hold: false,
        };
        input.files = vec![
            PackageFileInput::evidence_report(document_id, br#"{"status":"placeholder"}"#),
            PackageFileInput::pdfa_document(document_id, Some(act_id), b"%PDF-1.7\n%pdfa\n"),
        ];
        input
    }

    fn sample_input_with_evidence_index() -> PackageBuildInput {
        let mut input = sample_input();
        input.files.push(PackageFileInput::new(
            EVIDENCE_INDEX_PATH,
            PackageFileRole::EvidenceReport,
            JSON_CONTENT_TYPE,
            br#"{"schema":"chancela-test-evidence-index/v1"}"#,
        ));
        input
    }

    fn write_test_zip(members: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::default());

        if let Some(bytes) = members.get(MANIFEST_PATH) {
            zip.start_file(MANIFEST_PATH, opts).unwrap();
            zip.write_all(bytes).unwrap();
        }
        for (name, bytes) in members {
            if name == MANIFEST_PATH {
                continue;
            }
            zip.start_file(name, opts).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    fn tamper_manifest_json(
        package_bytes: &[u8],
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> Vec<u8> {
        let mut members = read_zip_members(package_bytes).unwrap();
        let manifest_bytes = members.get(MANIFEST_PATH).unwrap();
        let mut manifest_json: serde_json::Value = serde_json::from_slice(manifest_bytes).unwrap();
        mutate(&mut manifest_json);
        members.insert(
            MANIFEST_PATH.to_owned(),
            serde_json::to_vec_pretty(&manifest_json).unwrap(),
        );
        write_test_zip(&members)
    }

    #[test]
    fn build_package_from_manifest_writes_metadata_only_zip() {
        let package = build_package(sample_manifest()).unwrap();
        assert_eq!(package.id, id(1));
        assert_eq!(package.built_at, sample_created_at());
        assert_eq!(package.format, ArchiveFormat::Zip);

        let manifest = validate_package(&package.bytes).unwrap();
        assert_eq!(manifest.package_id, id(1));
        assert!(manifest.files.is_empty());
    }

    #[test]
    fn package_format_is_zip_manifest_then_sorted_members() {
        // Format v1: ZIP with manifest.json first, then content members sorted by path.
        let package = build_archive_package(sample_input()).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(&package.bytes)).unwrap();

        let names = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "manifest.json",
                "documents/00000000-0000-0000-0000-000000000005.pdf",
                "evidence/00000000-0000-0000-0000-000000000005.json",
            ]
        );

        let manifest = validate_package(&package.bytes).unwrap();
        assert_eq!(manifest.package_id, id(1));
        assert_eq!(manifest.created_at, sample_created_at());
        assert_eq!(manifest.entity_id, id(2));
        assert_eq!(manifest.book_id, id(3));
        assert_eq!(manifest.act_ids, vec![id(4)]);
        assert_eq!(manifest.document_ids, vec![id(5)]);
        assert_eq!(manifest.languages, vec!["pt-PT"]);
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(manifest.files[0].role, PackageFileRole::PdfA);
        assert_eq!(manifest.files[0].content_type, "application/pdf");
        assert_eq!(manifest.files[0].checksum.algorithm, "sha256");
        assert_eq!(
            manifest.files[0].checksum.hex_digest,
            sha256_hex(b"%PDF-1.7\n%pdfa\n")
        );
        assert_eq!(manifest.files[1].role, PackageFileRole::EvidenceReport);
        assert_eq!(manifest.files[1].content_type, "application/json");
    }

    #[test]
    fn manifest_contains_internal_dglab_aligned_preservation_metadata() {
        let package = build_archive_package(sample_input()).unwrap();
        let manifest = validate_package(&package.bytes).unwrap();
        let metadata = &manifest.preservation_interchange;

        assert_eq!(metadata.profile, PRESERVATION_INTERCHANGE_PROFILE);
        assert!(!metadata.official_dglab_interchange);
        assert!(!metadata.dglab_certification_claimed);
        assert_eq!(metadata.producer.name, "Chancela");
        assert_eq!(metadata.producer.system, "chancela-archive");
        assert_eq!(metadata.package_type, DEFAULT_PACKAGE_TYPE);
        assert_eq!(metadata.package_version, DEFAULT_PACKAGE_VERSION);
        assert_eq!(metadata.preservation_level, PreservationLevel::Managed);
        assert_eq!(metadata.classification, ClassificationMetadata::default());
        assert_eq!(metadata.retention, manifest.retention);
        assert_eq!(metadata.rights, manifest.rights);
        assert_eq!(metadata.languages, manifest.languages);
        assert_eq!(metadata.provenance.source_system, "chancela-archive");
        assert_eq!(metadata.provenance.record_count, manifest.provenance.len());
        assert_eq!(metadata.provenance.captured_record_count, 1);
        assert_eq!(metadata.fixity.algorithm, "sha256");
        assert_eq!(metadata.fixity.manifest_path, "manifest.json");
        assert_eq!(metadata.fixity.file_count, manifest.files.len());
        assert_eq!(
            metadata.fixity.total_byte_len,
            manifest.files.iter().map(|file| file.byte_len).sum::<u64>()
        );
    }

    #[test]
    fn readability_caveat_metadata_defaults_are_present_in_manifest() {
        let package = build_archive_package(sample_input()).unwrap();
        let second = build_archive_package(sample_input()).unwrap();
        let manifest = validate_package(&package.bytes).unwrap();
        let caveats = &manifest.preservation_interchange.readability_caveats;

        assert_eq!(caveats, &ReadabilityCaveatMetadata::default());
        assert_eq!(
            caveats.legal_archive_readability_mode,
            LegalArchiveReadabilityMode::ManifestOnly
        );
        assert!(!caveats.decryption_material_included);
        assert!(!caveats.external_import_verified);
        assert!(!caveats.legal_archive_certified);
        assert!(!caveats.zk_repository_mode);
        assert!(!caveats.zk_removes_gdpr_obligations);
        assert_eq!(
            package
                .manifest
                .preservation_interchange
                .readability_caveats,
            second.manifest.preservation_interchange.readability_caveats
        );

        let members = read_zip_members(&package.bytes).unwrap();
        let manifest_json: serde_json::Value =
            serde_json::from_slice(members.get(MANIFEST_PATH).unwrap()).unwrap();
        assert_eq!(
            manifest_json["preservation_interchange"]["readability_caveats"],
            serde_json::json!({
                "legal_archive_readability_mode": "manifest_only",
                "decryption_material_included": false,
                "external_import_verified": false,
                "legal_archive_certified": false,
                "zk_repository_mode": false,
                "zk_removes_gdpr_obligations": false
            })
        );
    }

    #[test]
    fn client_decrypted_readability_transfer_includes_bounded_documentation_only() {
        let repository_id = id(900);
        let mut input = sample_input();
        input.readability = ReadabilityExport::ClientDecryptedTransfer {
            source_repository_id: repository_id,
        };

        let package = build_archive_package(input).unwrap();
        let manifest = validate_package(&package.bytes).unwrap();
        let caveats = &manifest.preservation_interchange.readability_caveats;
        assert_eq!(
            caveats.legal_archive_readability_mode,
            LegalArchiveReadabilityMode::ClientDecryptedTransfer
        );
        assert!(caveats.zk_repository_mode);
        assert!(!caveats.decryption_material_included);
        assert!(!caveats.zk_removes_gdpr_obligations);
        assert_eq!(caveats.source_repository_id, Some(repository_id));
        assert_eq!(
            caveats.documentation_path.as_deref(),
            Some(READABILITY_DOCUMENTATION_PATH)
        );
        assert!(caveats.decryption_material_path.is_none());
        assert!(manifest.files.iter().any(|file| {
            file.path == READABILITY_DOCUMENTATION_PATH
                && file.role == PackageFileRole::ReadabilityDocumentation
        }));
        assert!(
            !manifest
                .files
                .iter()
                .any(|file| file.path == READABILITY_KEY_PACKAGE_PATH)
        );
        let members = read_zip_members(&package.bytes).unwrap();
        let documentation =
            std::str::from_utf8(members.get(READABILITY_DOCUMENTATION_PATH).unwrap()).unwrap();
        assert!(documentation.contains(&repository_id.to_string()));
        assert!(documentation.contains("does not remove GDPR obligations"));
        assert!(documentation.contains("does not certify a legal archive"));
    }

    #[test]
    fn encrypted_readability_transfer_tracks_compact_jwe_without_raw_key_fields() {
        let repository_id = id(901);
        let compact_jwe = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.ZW5jcnlwdGVkLWtleQ.aXY.Y2lwaGVydGV4dA.dGFn";
        let mut input = sample_input();
        input.readability = ReadabilityExport::EncryptedTransferWithPortableKeyPackage {
            source_repository_id: repository_id,
            portable_key_package_jwe: compact_jwe.to_owned(),
            recipient_instructions:
                "Obtain the recipient passphrase through the separately controlled custody channel."
                    .to_owned(),
        };

        let package = build_archive_package(input).unwrap();
        let manifest = validate_package(&package.bytes).unwrap();
        let caveats = &manifest.preservation_interchange.readability_caveats;
        assert_eq!(
            caveats.legal_archive_readability_mode,
            LegalArchiveReadabilityMode::EncryptedTransferWithPortableKeyPackage
        );
        assert!(caveats.zk_repository_mode);
        assert!(caveats.decryption_material_included);
        assert!(!caveats.external_import_verified);
        assert!(!caveats.legal_archive_certified);
        assert!(!caveats.zk_removes_gdpr_obligations);
        assert_eq!(caveats.source_repository_id, Some(repository_id));
        assert_eq!(
            caveats.decryption_material_path.as_deref(),
            Some(READABILITY_KEY_PACKAGE_PATH)
        );
        let key_file = manifest
            .files
            .iter()
            .find(|file| file.path == READABILITY_KEY_PACKAGE_PATH)
            .unwrap();
        assert_eq!(key_file.role, PackageFileRole::EncryptedDecryptionMaterial);
        assert_eq!(key_file.content_type, "application/jose");
        let members = read_zip_members(&package.bytes).unwrap();
        assert_eq!(
            members.get(READABILITY_KEY_PACKAGE_PATH).unwrap(),
            compact_jwe.as_bytes()
        );
        let serialized = serde_json::to_string(&manifest).unwrap();
        for forbidden in ["raw_key", "plaintext_key", "private_key", "recovery_share"] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn encrypted_readability_transfer_rejects_raw_or_malformed_material_and_reserved_paths() {
        let mut raw = sample_input();
        raw.readability = ReadabilityExport::EncryptedTransferWithPortableKeyPackage {
            source_repository_id: id(902),
            portable_key_package_jwe: "this-is-a-raw-key-not-a-jwe".to_owned(),
            recipient_instructions: "Out-of-band secret delivery.".to_owned(),
        };
        assert!(
            matches!(build_archive_package(raw), Err(ArchiveError::InvalidManifest(message)) if message.contains("JWE"))
        );

        let mut collision = sample_input();
        collision.readability = ReadabilityExport::ClientDecryptedTransfer {
            source_repository_id: id(903),
        };
        collision.files.push(PackageFileInput::new(
            READABILITY_DOCUMENTATION_PATH,
            PackageFileRole::Other,
            "text/plain",
            b"caller collision".to_vec(),
        ));
        assert!(matches!(
            build_archive_package(collision),
            Err(ArchiveError::DuplicatePath(path)) if path == READABILITY_DOCUMENTATION_PATH
        ));
    }

    #[test]
    fn readability_caveats_default_when_missing_from_v1_manifest() {
        let package = build_archive_package(sample_input()).unwrap();
        let legacy = tamper_manifest_json(&package.bytes, |manifest| {
            manifest["preservation_interchange"]
                .as_object_mut()
                .unwrap()
                .remove("readability_caveats");
        });

        let manifest = validate_package(&legacy).unwrap();
        assert_eq!(
            manifest.preservation_interchange.readability_caveats,
            ReadabilityCaveatMetadata::default()
        );
    }

    #[test]
    fn local_dglab_interchange_manifest_generation_is_deterministic() {
        let package = build_archive_package(sample_input_with_evidence_index()).unwrap();
        let package_bytes = package.bytes.clone();

        let first = build_local_dglab_interchange_manifest(&package.manifest).unwrap();
        let second = build_local_dglab_interchange_manifest(&package.manifest).unwrap();

        assert_eq!(package.bytes, package_bytes);
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string_pretty(&first).unwrap(),
            serde_json::to_string_pretty(&second).unwrap()
        );
        validate_local_dglab_interchange_manifest(&first, &package.manifest).unwrap();

        assert_eq!(first.schema, LOCAL_DGLAB_INTERCHANGE_MANIFEST_SCHEMA);
        assert_eq!(first.profile, LOCAL_DGLAB_INTERCHANGE_MANIFEST_PROFILE);
        assert_eq!(first.package_id, package.manifest.package_id);
        assert_eq!(first.source_manifest_path, MANIFEST_PATH);
        assert!(!first.official_dglab_interchange);
        assert!(!first.dglab_certification_claimed);
        assert!(!first.external_dglab_approval_obtained);
        assert!(!first.legal_archive_certified);
        assert!(!first.destructive_disposal_performed);
        assert_eq!(
            first.producer,
            package.manifest.preservation_interchange.producer
        );
        assert_eq!(
            first.package_type,
            package.manifest.preservation_interchange.package_type
        );
        assert_eq!(
            first.package_version,
            package.manifest.preservation_interchange.package_version
        );
        assert_eq!(
            first.preservation_level,
            package.manifest.preservation_level
        );
        assert_eq!(
            first.local_classification,
            package.manifest.preservation_interchange.classification
        );
        assert_eq!(first.rights, package.manifest.rights);
        assert_eq!(first.languages, package.manifest.languages);
        assert_eq!(first.retention, package.manifest.retention);
        assert_eq!(first.file_fixity_summary.algorithm, SHA256);
        assert_eq!(
            first.file_fixity_summary.file_count,
            package.manifest.files.len()
        );
        assert_eq!(
            first.file_fixity_summary.total_byte_len,
            package
                .manifest
                .files
                .iter()
                .map(|file| file.byte_len)
                .sum::<u64>()
        );
        assert_eq!(
            first.evidence_index_path.as_deref(),
            Some(EVIDENCE_INDEX_PATH)
        );
        assert_eq!(first.files.len(), package.manifest.files.len());
        for pair in first.files.windows(2) {
            assert!(pair[0].path < pair[1].path);
        }
    }

    #[test]
    fn local_dglab_interchange_validator_rejects_any_true_claim_flag() {
        let package = build_archive_package(sample_input()).unwrap();
        let valid = build_local_dglab_interchange_manifest(&package.manifest).unwrap();
        type ClaimFlagCase = (&'static str, fn(&mut LocalDglabInterchangeManifest));
        let cases: [ClaimFlagCase; 5] = [
            ("official_dglab_interchange", |manifest| {
                manifest.official_dglab_interchange = true
            }),
            ("dglab_certification_claimed", |manifest| {
                manifest.dglab_certification_claimed = true
            }),
            ("external_dglab_approval_obtained", |manifest| {
                manifest.external_dglab_approval_obtained = true
            }),
            ("legal_archive_certified", |manifest| {
                manifest.legal_archive_certified = true
            }),
            ("destructive_disposal_performed", |manifest| {
                manifest.destructive_disposal_performed = true
            }),
        ];

        for (flag, mutate) in cases {
            let mut tampered = valid.clone();
            mutate(&mut tampered);
            assert!(
                matches!(
                    validate_local_dglab_interchange_manifest(&tampered, &package.manifest),
                    Err(ArchiveError::InvalidManifest(message)) if message.contains(flag)
                ),
                "{flag} must be rejected when true"
            );
        }
    }

    #[test]
    fn local_dglab_interchange_validator_rejects_mismatches_unsafe_paths_and_blanks() {
        let package = build_archive_package(sample_input()).unwrap();
        let valid = build_local_dglab_interchange_manifest(&package.manifest).unwrap();

        let mut mismatched_package_id = valid.clone();
        mismatched_package_id.package_id = id(99);
        assert!(matches!(
            validate_local_dglab_interchange_manifest(
                &mismatched_package_id,
                &package.manifest
            ),
            Err(ArchiveError::InvalidManifest(message)) if message.contains("package_id")
        ));

        let mut mismatched_file_count = valid.clone();
        mismatched_file_count.file_fixity_summary.file_count += 1;
        assert!(matches!(
            validate_local_dglab_interchange_manifest(
                &mismatched_file_count,
                &package.manifest
            ),
            Err(ArchiveError::InvalidManifest(message)) if message.contains("file_count")
        ));

        let mut mismatched_total_bytes = valid.clone();
        mismatched_total_bytes.file_fixity_summary.total_byte_len += 1;
        assert!(matches!(
            validate_local_dglab_interchange_manifest(
                &mismatched_total_bytes,
                &package.manifest
            ),
            Err(ArchiveError::InvalidManifest(message)) if message.contains("total_byte_len")
        ));

        let mut unsafe_source_path = valid.clone();
        unsafe_source_path.source_manifest_path = "../manifest.json".to_owned();
        assert_eq!(
            validate_local_dglab_interchange_manifest(&unsafe_source_path, &package.manifest),
            Err(ArchiveError::InvalidPath("../manifest.json".to_owned()))
        );

        let mut unsafe_file_path = valid.clone();
        unsafe_file_path.files[0].path = "../escape.pdf".to_owned();
        assert_eq!(
            validate_local_dglab_interchange_manifest(&unsafe_file_path, &package.manifest),
            Err(ArchiveError::InvalidPath("../escape.pdf".to_owned()))
        );

        let mut unsorted_files = valid.clone();
        unsorted_files.files.reverse();
        assert!(matches!(
            validate_local_dglab_interchange_manifest(&unsorted_files, &package.manifest),
            Err(ArchiveError::InvalidManifest(message)) if message.contains("sorted")
        ));

        let mut blank_profile = valid.clone();
        blank_profile.profile = " ".to_owned();
        assert!(matches!(
            validate_local_dglab_interchange_manifest(&blank_profile, &package.manifest),
            Err(ArchiveError::InvalidManifest(message)) if message.contains("profile")
        ));

        let mut blank_producer = valid.clone();
        blank_producer.producer.name = " ".to_owned();
        assert!(matches!(
            validate_local_dglab_interchange_manifest(&blank_producer, &package.manifest),
            Err(ArchiveError::InvalidManifest(message)) if message.contains("producer.name")
        ));
    }

    #[test]
    fn package_build_is_deterministic_for_same_inputs() {
        let first = build_archive_package(sample_input()).unwrap();
        let second = build_archive_package(sample_input()).unwrap();
        assert_eq!(first.bytes, second.bytes);
        assert_eq!(first.manifest, second.manifest);
    }

    #[test]
    fn build_sorts_and_deduplicates_ids_and_languages() {
        let mut input = sample_input();
        input.act_ids = vec![id(9), id(4), id(9)];
        input.document_ids = vec![id(7), id(5), id(7)];
        input.languages = vec![" pt-PT ".into(), "en-GB".into(), "pt-PT".into()];

        let package = build_archive_package(input).unwrap();

        assert_eq!(package.manifest.act_ids, vec![id(4), id(9)]);
        assert_eq!(package.manifest.document_ids, vec![id(5), id(7)]);
        assert_eq!(package.manifest.languages, vec!["en-GB", "pt-PT"]);
        assert_eq!(
            package.manifest.preservation_interchange.languages,
            vec!["en-GB", "pt-PT"]
        );
    }

    #[test]
    fn validation_rejects_checksum_mismatch() {
        let package = build_archive_package(sample_input()).unwrap();
        let manifest = package.manifest;
        let mut members = BTreeMap::new();
        members.insert(
            "documents/00000000-0000-0000-0000-000000000005.pdf".to_owned(),
            b"%PDF-1.7\nBAD!!\n".to_vec(),
        );
        members.insert(
            "evidence/00000000-0000-0000-0000-000000000005.json".to_owned(),
            br#"{"status":"placeholder"}"#.to_vec(),
        );
        let tampered = write_package_zip(&manifest, &members).unwrap();

        assert!(matches!(
            validate_package(&tampered),
            Err(ArchiveError::ChecksumMismatch { path, .. })
                if path == "documents/00000000-0000-0000-0000-000000000005.pdf"
        ));
    }

    #[test]
    fn validation_rejects_missing_manifest() {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::default());
        zip.start_file("documents/only.pdf", opts).unwrap();
        zip.write_all(b"%PDF").unwrap();
        let bytes = zip.finish().unwrap().into_inner();

        assert_eq!(
            validate_package(&bytes),
            Err(ArchiveError::InvalidPackage(
                "missing manifest.json".to_owned()
            ))
        );
    }

    #[test]
    fn build_rejects_unsafe_paths() {
        for path in [
            "../escape.pdf",
            "/absolute.pdf",
            "\\absolute.pdf",
            "C:/absolute.pdf",
            "documents\\bad.pdf",
            "documents//bad.pdf",
            "documents/./bad.pdf",
            "manifest.json",
        ] {
            let mut input = PackageBuildInput::new(id(1), sample_created_at(), id(2), id(3));
            input.languages = vec!["pt-PT".to_owned()];
            input.files = vec![PackageFileInput::new(
                path,
                PackageFileRole::PdfA,
                "application/pdf",
                b"%PDF",
            )];

            assert!(
                matches!(build_archive_package(input), Err(ArchiveError::InvalidPath(p)) if p == path),
                "path {path} must be rejected"
            );
        }
    }

    #[test]
    fn validation_rejects_missing_and_blank_preservation_metadata() {
        let package = build_archive_package(sample_input()).unwrap();
        let missing = tamper_manifest_json(&package.bytes, |manifest| {
            manifest
                .as_object_mut()
                .unwrap()
                .remove("preservation_interchange");
        });
        assert!(
            matches!(validate_package(&missing), Err(ArchiveError::InvalidManifest(message)) if message.contains("preservation_interchange")),
            "missing preservation_interchange must fail"
        );

        let mut manifest = sample_manifest();
        manifest.preservation_interchange.producer.name = "   ".to_owned();
        assert!(
            matches!(validate_manifest(&manifest), Err(ArchiveError::InvalidManifest(message)) if message.contains("producer.name")),
            "blank producer name must fail"
        );
    }

    #[test]
    fn validation_rejects_blank_rights_language_classification_and_retention_metadata() {
        let mut manifest = sample_manifest();
        manifest.rights.holder = Some(" ".to_owned());
        manifest.preservation_interchange.rights = manifest.rights.clone();
        assert!(
            matches!(validate_manifest(&manifest), Err(ArchiveError::InvalidManifest(message)) if message.contains("rights.holder"))
        );

        let mut manifest = sample_manifest();
        manifest.languages = vec!["pt-PT".to_owned(), " ".to_owned()];
        manifest.preservation_interchange.languages = manifest.languages.clone();
        assert!(
            matches!(validate_manifest(&manifest), Err(ArchiveError::InvalidManifest(message)) if message.contains("languages"))
        );

        let mut manifest = sample_manifest();
        manifest.preservation_interchange.classification.code = Some(" ".to_owned());
        assert!(
            matches!(validate_manifest(&manifest), Err(ArchiveError::InvalidManifest(message)) if message.contains("classification.code"))
        );

        let mut manifest = sample_manifest();
        manifest.retention.schedule_id = Some(" ".to_owned());
        manifest.preservation_interchange.retention = manifest.retention.clone();
        assert!(
            matches!(validate_manifest(&manifest), Err(ArchiveError::InvalidManifest(message)) if message.contains("retention.schedule_id"))
        );
    }

    #[test]
    fn validation_rejects_duplicate_ids_and_non_deterministic_ordering() {
        let mut duplicate_acts = sample_manifest();
        duplicate_acts.act_ids = vec![id(4), id(4)];
        assert!(
            matches!(validate_manifest(&duplicate_acts), Err(ArchiveError::InvalidManifest(message)) if message.contains("duplicate id in act_ids"))
        );

        let mut duplicate_documents = sample_manifest();
        duplicate_documents.document_ids = vec![id(5), id(5)];
        assert!(
            matches!(validate_manifest(&duplicate_documents), Err(ArchiveError::InvalidManifest(message)) if message.contains("duplicate id in document_ids"))
        );

        let mut unsorted_languages = sample_manifest();
        unsorted_languages.languages = vec!["pt-PT".to_owned(), "en-GB".to_owned()];
        unsorted_languages.preservation_interchange.languages =
            unsorted_languages.languages.clone();
        assert!(
            matches!(validate_manifest(&unsorted_languages), Err(ArchiveError::InvalidManifest(message)) if message.contains("languages must be sorted"))
        );

        let mut unsorted_files = build_archive_package(sample_input()).unwrap().manifest;
        unsorted_files.files.reverse();
        unsorted_files.preservation_interchange.fixity.file_count = unsorted_files.files.len();
        unsorted_files
            .preservation_interchange
            .fixity
            .total_byte_len = unsorted_files.files.iter().map(|file| file.byte_len).sum();
        assert!(
            matches!(validate_manifest(&unsorted_files), Err(ArchiveError::InvalidManifest(message)) if message.contains("files must be sorted"))
        );
    }

    #[test]
    fn validate_package_rejects_path_like_member_names() {
        let package = build_archive_package(sample_input()).unwrap();
        let mut members = read_zip_members(&package.bytes).unwrap();
        members.insert("C:/escape.pdf".to_owned(), b"%PDF".to_vec());
        let tampered = write_test_zip(&members);

        assert_eq!(
            validate_package(&tampered),
            Err(ArchiveError::InvalidPath("C:/escape.pdf".to_owned()))
        );
    }

    #[test]
    fn validate_package_rejects_untracked_missing_and_bad_length_members() {
        let package = build_archive_package(sample_input()).unwrap();

        let mut members = read_zip_members(&package.bytes).unwrap();
        members.insert("extra/member.json".to_owned(), b"{}".to_vec());
        let untracked = write_test_zip(&members);
        assert!(
            matches!(validate_package(&untracked), Err(ArchiveError::InvalidPackage(message)) if message.contains("untracked member extra/member.json"))
        );

        let mut members = read_zip_members(&package.bytes).unwrap();
        members.remove("documents/00000000-0000-0000-0000-000000000005.pdf");
        let missing = write_test_zip(&members);
        assert_eq!(
            validate_package(&missing),
            Err(ArchiveError::MissingArtifact(
                "documents/00000000-0000-0000-0000-000000000005.pdf".to_owned()
            ))
        );

        let bad_length = tamper_manifest_json(&package.bytes, |manifest| {
            let files = manifest["files"].as_array_mut().unwrap();
            files[0]["byte_len"] = serde_json::json!(999);
            manifest["preservation_interchange"]["fixity"]["total_byte_len"] =
                serde_json::json!(999 + files[1]["byte_len"].as_u64().unwrap());
        });
        assert!(
            matches!(validate_package(&bad_length), Err(ArchiveError::InvalidPackage(message)) if message.contains("byte length mismatch"))
        );
    }

    #[test]
    fn validation_rejects_dglab_interchange_or_certification_claims() {
        let mut manifest = sample_manifest();
        manifest.preservation_interchange.official_dglab_interchange = true;
        assert!(
            matches!(validate_manifest(&manifest), Err(ArchiveError::InvalidManifest(message)) if message.contains("official_dglab_interchange"))
        );

        let mut manifest = sample_manifest();
        manifest
            .preservation_interchange
            .dglab_certification_claimed = true;
        assert!(
            matches!(validate_manifest(&manifest), Err(ArchiveError::InvalidManifest(message)) if message.contains("dglab_certification_claimed"))
        );
    }

    #[test]
    fn readability_caveat_validation_rejects_any_true_overclaim_flag() {
        type ClaimFlagCase = (&'static str, fn(&mut ReadabilityCaveatMetadata));
        let cases: [ClaimFlagCase; 5] = [
            ("decryption_material_included", |caveats| {
                caveats.decryption_material_included = true
            }),
            ("external_import_verified", |caveats| {
                caveats.external_import_verified = true
            }),
            ("legal_archive_certified", |caveats| {
                caveats.legal_archive_certified = true
            }),
            ("zk_repository_mode", |caveats| {
                caveats.zk_repository_mode = true
            }),
            ("zk_removes_gdpr_obligations", |caveats| {
                caveats.zk_removes_gdpr_obligations = true
            }),
        ];

        for (flag, mutate) in cases {
            let mut manifest = sample_manifest();
            mutate(&mut manifest.preservation_interchange.readability_caveats);
            assert!(
                matches!(
                    validate_manifest(&manifest),
                    Err(ArchiveError::InvalidManifest(message)) if message.contains(flag)
                ),
                "{flag} must be rejected when true"
            );
        }
    }

    #[test]
    fn readability_caveats_reject_unknown_manifest_fields() {
        let package = build_archive_package(sample_input()).unwrap();
        for field in [
            "decryption_key",
            "sync_target",
            "custody_proof",
            "official_dglab_interchange",
            "dglab_certification_claimed",
        ] {
            let tampered = tamper_manifest_json(&package.bytes, |manifest| {
                manifest["preservation_interchange"]["readability_caveats"][field] =
                    serde_json::json!(true);
            });

            assert!(
                matches!(
                    validate_package(&tampered),
                    Err(ArchiveError::InvalidManifest(message))
                        if message.contains("unknown field") && message.contains(field)
                ),
                "{field} must not be accepted under readability_caveats"
            );
        }
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
