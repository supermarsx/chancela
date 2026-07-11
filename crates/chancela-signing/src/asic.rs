//! ASiC evidence-container support.
//!
//! This module owns the ZIP layout and manifest bytes for the ASiC containers this crate produces
//! and reads. The *bounded* single-signature shapes — one ASiC-S payload plus one detached CAdES-B
//! signature, or an ASiC-E/CAdES container with one `ASiCManifest` over one CAdES signature — are
//! parsed strictly by [`extract_asic_container`] and classified by [`inspect_asic_profile`].
//!
//! The full ASiC surface builds on the same byte primitives: [`create_asic_s_xades_container`]
//! (ASiC-S/XAdES), [`assemble_asic_e_container`] + [`build_asic_e_manifest`] (ASiC-E multi-signature
//! with a per-signature `ASiCManifest`), and [`build_asic_archive_manifest`] (an ETSI EN 319 162
//! `ASiCArchiveManifest` protected by an RFC 3161 archive timestamp). Signing orchestration lives in
//! [`crate::asic_sign`] and the cryptographic validation surface in [`crate::asic_validate`]. None
//! of it makes a legal qualification decision.

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Write};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use crate::{SignatureFormat, SigningError, UnsupportedSignatureProfile};

/// The ASiC-S MIME type stored in the first, uncompressed ZIP member.
pub const ASICS_MIMETYPE: &str = "application/vnd.etsi.asic-s+zip";
/// The ASiC-E MIME type stored in the first, uncompressed ZIP member.
pub const ASICE_MIMETYPE: &str = "application/vnd.etsi.asic-e+zip";
/// The detached CAdES signature member this implementation creates and validates.
pub const ASICS_CADES_SIGNATURE_PATH: &str = "META-INF/signatures.p7s";
/// The ASiC-E manifest member this implementation creates and validates.
pub const ASICE_MANIFEST_PATH: &str = "META-INF/ASiCManifest.xml";
/// The ASiC-E detached CAdES signature member this implementation creates and validates.
pub const ASICE_CADES_SIGNATURE_PATH: &str = "META-INF/signature001.p7s";
/// The detached XAdES signature member for an ASiC-S/XAdES container.
pub const ASICS_XADES_SIGNATURE_PATH: &str = "META-INF/signatures.xml";
/// The ASiC-E archive manifest member (ETSI EN 319 162 archival/time-assertion manifest).
///
/// Note this is `ASiCArchiveManifest.xml`, *not* an `ASiCManifest*.xml`: the two are distinct
/// members with distinct roles, so the archive manifest is deliberately not matched by the
/// per-signature manifest detector.
pub const ASICE_ARCHIVE_MANIFEST_PATH: &str = "META-INF/ASiCArchiveManifest.xml";
/// The RFC 3161 archive-timestamp token member protecting [`ASICE_ARCHIVE_MANIFEST_PATH`].
pub const ASICE_ARCHIVE_TIMESTAMP_PATH: &str = "META-INF/ASiCArchiveManifest.tst";
/// The media type recorded on an archive manifest's `SigReference` to the RFC 3161 token.
pub const RFC3161_TIMESTAMP_MIME_TYPE: &str = "application/vnd.etsi.timestamp-token";
/// The media type recorded on a detached XAdES `SigReference`/member.
pub const XADES_SIGNATURE_MIME_TYPE: &str = "application/vnd.etsi.asic-e+xml";
/// Maximum declared or actual uncompressed size accepted for one ASiC ZIP member.
pub const ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum total uncompressed size accepted across ASiC ZIP members.
pub const ASIC_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES: u64 = 32 * 1024 * 1024;

const MIMETYPE_PATH: &str = "mimetype";
const META_INF_PREFIX: &str = "META-INF/";
const ASIC_NS: &str = "http://uri.etsi.org/02918/v1.2.1#";
const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const SHA256_DIGEST_METHOD_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const CADES_SIGNATURE_MIME_TYPE: &str = "application/pkcs7-signature";

/// A parsed single-payload ASiC-S/CAdES container.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicSContainer {
    /// The payload member name inside the ZIP container.
    pub content_name: String,
    /// The payload bytes that the detached CAdES signature covers.
    pub content: Vec<u8>,
    /// DER `ContentInfo` bytes from `META-INF/signatures.p7s`.
    pub cades_signature_der: Vec<u8>,
}

/// One payload to include in a bounded ASiC-E/CAdES container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsicPayload<'a> {
    /// The payload member name inside the ASiC ZIP container.
    pub name: &'a str,
    /// The payload bytes referenced by the ASiC manifest.
    pub bytes: &'a [u8],
    /// Optional media type recorded on the manifest's `DataObjectReference`.
    pub mime_type: Option<&'a str>,
}

/// A parsed ASiC-E data object whose digest matched the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicEDataObject {
    /// The payload member name inside the ZIP container.
    pub name: String,
    /// The payload bytes.
    pub bytes: Vec<u8>,
    /// Optional media type from the manifest's `DataObjectReference`.
    pub mime_type: Option<String>,
    /// SHA-256 digest verified against the manifest.
    pub sha256_digest: [u8; 32],
}

/// A parsed bounded ASiC-E/CAdES container.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicEContainer {
    /// The ASiCManifest XML bytes that the detached CAdES signature covers.
    pub manifest: Vec<u8>,
    /// The signature member referenced by the manifest.
    pub signature_path: String,
    /// DER `ContentInfo` bytes from the referenced CAdES signature member.
    pub cades_signature_der: Vec<u8>,
    /// Payload objects whose SHA-256 digests matched the manifest.
    pub data_objects: Vec<AsicEDataObject>,
}

/// A parsed ASiC container in one of the bounded shapes implemented by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsicContainer {
    /// Single-payload ASiC-S/CAdES.
    S(AsicSContainer),
    /// ASiC-E/CAdES with one manifest and one detached CAdES signature over that manifest.
    E(AsicEContainer),
}

/// ASiC container family declared by the ZIP `mimetype` member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsicContainerKind {
    /// ASiC-S ZIP container.
    AsicS,
    /// ASiC-E ZIP container.
    AsicE,
}

impl AsicContainerKind {
    fn mimetype(self) -> &'static str {
        match self {
            AsicContainerKind::AsicS => ASICS_MIMETYPE,
            AsicContainerKind::AsicE => ASICE_MIMETYPE,
        }
    }

    fn label(self) -> &'static str {
        match self {
            AsicContainerKind::AsicS => "ASiC-S",
            AsicContainerKind::AsicE => "ASiC-E",
        }
    }
}

/// Signature technology indicated by the ASiC signature members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsicSignatureProfile {
    /// One or more CAdES `.p7s` signature members.
    Cades,
    /// One or more XAdES XML signature members.
    Xades,
    /// Both CAdES and XAdES signature members were found.
    Mixed,
    /// No recognised ASiC signature member was found.
    Unsigned,
}

/// Bounded ASiC profiles this crate can attempt to parse and validate today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsicBoundedProfile {
    /// ASiC-S with exactly one payload and one detached CAdES signature at
    /// `META-INF/signatures.p7s`.
    AsicSCadesSinglePayload,
    /// ASiC-E with one `META-INF/ASiCManifest.xml` and one referenced CAdES `.p7s` signature.
    AsicECadesSingleManifest,
}

/// Diagnostic ASiC profile shape inferred from ZIP members.
///
/// This is a structural classifier only. It does not assert XAdES validation, CAdES trust,
/// long-term evidence, legal validity, or production compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsicProfileShape {
    /// Bounded ASiC-S/CAdES single-payload shape.
    AsicSCadesSinglePayload,
    /// ASiC-S with CAdES members, but outside the bounded single-payload shape.
    AsicSCadesUnsupported,
    /// ASiC-S carrying XAdES XML signature members.
    AsicSXades,
    /// ASiC-S carrying both CAdES and XAdES signature members.
    AsicSMixed,
    /// ASiC-S with no recognised signature members.
    AsicSUnsigned,
    /// Bounded ASiC-E/CAdES single-manifest shape.
    AsicECadesSingleManifest,
    /// ASiC-E with CAdES members, but outside the bounded single-manifest shape.
    AsicECadesUnsupported,
    /// ASiC-E carrying XAdES XML signature members.
    AsicEXades,
    /// ASiC-E carrying both CAdES and XAdES signature members.
    AsicEMixed,
    /// ASiC-E with no recognised signature members.
    AsicEUnsigned,
}

/// Signature member technology identified by member path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsicSignatureMemberKind {
    /// CAdES/CMS `.p7s` member.
    Cades,
    /// XAdES XML member.
    Xades,
}

/// Stable blocker identifiers for ASiC diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AsicDiagnosticBlockerId {
    /// The ZIP contains the same member name more than once.
    DuplicateMember,
    /// The ZIP member is encrypted.
    EncryptedMember,
    /// A ZIP member declares or decompresses to more bytes than the bounded ASiC reader accepts.
    MemberUncompressedSizeExceeded,
    /// ZIP members declare or decompress to more total bytes than the bounded ASiC reader accepts.
    TotalUncompressedSizeExceeded,
    /// XAdES was detected; this crate does not validate XAdES.
    XadesNotSupported,
    /// A `META-INF` member is outside the bounded ASiC/CAdES slice.
    UnsupportedMetaInfMember,
    /// ASiC-S did not contain exactly one payload member.
    AsicSRequiresSinglePayload,
    /// ASiC-S included an ASiCManifest member.
    AsicSManifestUnsupported,
    /// ASiC-S did not contain the required CAdES signature member.
    AsicSMissingCadesSignature,
    /// ASiC-S used a CAdES signature path outside the bounded implementation.
    AsicSUnsupportedCadesSignaturePath,
    /// ASiC-E did not contain any payload members.
    AsicERequiresPayload,
    /// ASiC-E did not contain `META-INF/ASiCManifest.xml`.
    AsicEMissingManifest,
    /// ASiC-E used a manifest path outside the bounded implementation.
    AsicEUnsupportedManifestPath,
    /// ASiC-E contained more than one ASiCManifest member.
    AsicEMultipleManifests,
    /// ASiC-E did not contain a CAdES signature member.
    AsicEMissingCadesSignature,
    /// ASiC-E contained more than one CAdES signature member.
    AsicEMultipleCadesSignatures,
    /// A CAdES signature member was present but empty.
    EmptySignatureMember,
    /// An ASiC-E manifest member was present but empty.
    EmptyManifestMember,
    /// The bounded diagnostic parser could not parse an ASiC-E manifest.
    AsicEManifestParseFailed,
    /// An ASiC-E manifest referenced a signature member missing from the ZIP.
    AsicEManifestReferencesMissingSignature,
    /// An ASiC-E CAdES signature member was not referenced by the parsed manifest.
    AsicEUnreferencedSignature,
    /// An ASiC-E manifest referenced a payload missing from the ZIP.
    AsicEManifestReferencesMissingPayload,
    /// An ASiC-E payload member was not referenced by the parsed manifest.
    AsicEManifestUnreferencedPayload,
    /// An ASiC-E manifest payload digest did not match the packaged payload bytes.
    AsicEManifestDigestMismatch,
}

impl AsicDiagnosticBlockerId {
    /// Stable snake-case identifier for logs or API payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            AsicDiagnosticBlockerId::DuplicateMember => "duplicate_member",
            AsicDiagnosticBlockerId::EncryptedMember => "encrypted_member",
            AsicDiagnosticBlockerId::MemberUncompressedSizeExceeded => {
                "member_uncompressed_size_exceeded"
            }
            AsicDiagnosticBlockerId::TotalUncompressedSizeExceeded => {
                "total_uncompressed_size_exceeded"
            }
            AsicDiagnosticBlockerId::XadesNotSupported => "xades_not_supported",
            AsicDiagnosticBlockerId::UnsupportedMetaInfMember => "unsupported_meta_inf_member",
            AsicDiagnosticBlockerId::AsicSRequiresSinglePayload => "asic_s_requires_single_payload",
            AsicDiagnosticBlockerId::AsicSManifestUnsupported => "asic_s_manifest_unsupported",
            AsicDiagnosticBlockerId::AsicSMissingCadesSignature => "asic_s_missing_cades_signature",
            AsicDiagnosticBlockerId::AsicSUnsupportedCadesSignaturePath => {
                "asic_s_unsupported_cades_signature_path"
            }
            AsicDiagnosticBlockerId::AsicERequiresPayload => "asic_e_requires_payload",
            AsicDiagnosticBlockerId::AsicEMissingManifest => "asic_e_missing_manifest",
            AsicDiagnosticBlockerId::AsicEUnsupportedManifestPath => {
                "asic_e_unsupported_manifest_path"
            }
            AsicDiagnosticBlockerId::AsicEMultipleManifests => "asic_e_multiple_manifests",
            AsicDiagnosticBlockerId::AsicEMissingCadesSignature => "asic_e_missing_cades_signature",
            AsicDiagnosticBlockerId::AsicEMultipleCadesSignatures => {
                "asic_e_multiple_cades_signatures"
            }
            AsicDiagnosticBlockerId::EmptySignatureMember => "empty_signature_member",
            AsicDiagnosticBlockerId::EmptyManifestMember => "empty_manifest_member",
            AsicDiagnosticBlockerId::AsicEManifestParseFailed => "asic_e_manifest_parse_failed",
            AsicDiagnosticBlockerId::AsicEManifestReferencesMissingSignature => {
                "asic_e_manifest_references_missing_signature"
            }
            AsicDiagnosticBlockerId::AsicEUnreferencedSignature => "asic_e_unreferenced_signature",
            AsicDiagnosticBlockerId::AsicEManifestReferencesMissingPayload => {
                "asic_e_manifest_references_missing_payload"
            }
            AsicDiagnosticBlockerId::AsicEManifestUnreferencedPayload => {
                "asic_e_manifest_unreferenced_payload"
            }
            AsicDiagnosticBlockerId::AsicEManifestDigestMismatch => {
                "asic_e_manifest_digest_mismatch"
            }
        }
    }
}

/// One structured reason the bounded ASiC/CAdES implementation cannot handle a container shape.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicDiagnosticBlocker {
    /// Stable blocker identifier.
    pub id: AsicDiagnosticBlockerId,
    /// Human-readable diagnostic detail.
    pub message: String,
    /// ZIP member path most directly associated with this blocker, when applicable.
    pub member_path: Option<String>,
}

/// Per-signature-member diagnostic information.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicSignatureDiagnostic {
    /// ZIP member path.
    pub path: String,
    /// Signature member technology inferred from the member path.
    pub member_kind: AsicSignatureMemberKind,
    /// Uncompressed ZIP member size in bytes.
    pub size: u64,
    /// ASiCManifest member paths that reference this signature member.
    pub referenced_by_manifest_paths: Vec<String>,
    /// Signature-member-local blockers.
    pub blockers: Vec<AsicDiagnosticBlocker>,
}

/// One `SigReference` found by the bounded ASiC-E manifest diagnostic parser.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicManifestSignatureReferenceDiagnostic {
    /// Referenced signature URI.
    pub uri: String,
    /// Whether a ZIP member with this path exists.
    pub member_present: bool,
    /// Inferred signature member kind, when the referenced member exists and is recognised.
    pub member_kind: Option<AsicSignatureMemberKind>,
}

/// One `DataObjectReference` found by the bounded ASiC-E manifest diagnostic parser.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicManifestDataObjectDiagnostic {
    /// Referenced payload URI.
    pub uri: String,
    /// Optional media type from the manifest.
    pub mime_type: Option<String>,
    /// Whether a ZIP payload member with this path exists.
    pub payload_present: bool,
    /// SHA-256 digest declared in the manifest.
    pub sha256_digest: [u8; 32],
    /// Local digest comparison against packaged bytes, when the payload is present.
    pub digest_matches: Option<bool>,
}

/// Per-ASiCManifest diagnostic information.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicManifestDiagnostic {
    /// ZIP member path.
    pub path: String,
    /// Uncompressed ZIP member size in bytes.
    pub size: u64,
    /// `SigReference` entries parsed by the bounded diagnostic parser.
    pub signature_references: Vec<AsicManifestSignatureReferenceDiagnostic>,
    /// `DataObjectReference` entries parsed by the bounded diagnostic parser.
    pub data_object_references: Vec<AsicManifestDataObjectDiagnostic>,
    /// Manifest-local blockers.
    pub blockers: Vec<AsicDiagnosticBlocker>,
}

/// ZIP/member-level ASiC profile report.
///
/// This is a diagnostic classifier only: it does not validate CAdES cryptography, validate XAdES
/// XML, timestamps, trust, LTV evidence, legal validity, or production compliance.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicProfileReport {
    /// Container family from the strict first ZIP `mimetype` member.
    pub container_kind: AsicContainerKind,
    /// Exact mimetype value expected for the container family.
    pub mimetype: &'static str,
    /// ZIP member names in archive order.
    pub member_names: Vec<String>,
    /// Non-`META-INF`, non-`mimetype` payload member paths.
    pub payload_paths: Vec<String>,
    /// `META-INF/ASiCManifest*.xml` members.
    pub manifest_paths: Vec<String>,
    /// CAdES `.p7s` signature members.
    pub cades_signature_paths: Vec<String>,
    /// XAdES XML signature members.
    pub xades_signature_paths: Vec<String>,
    /// Other `META-INF` members outside this bounded implementation.
    pub unsupported_meta_inf_paths: Vec<String>,
    /// Signature technology inferred from signature member names.
    pub signature_profile: AsicSignatureProfile,
    /// More specific structural profile shape inferred from members.
    pub profile_shape: AsicProfileShape,
    /// Bounded profile candidate if the member shape matches a supported ASiC/CAdES slice.
    pub bounded_profile: Option<AsicBoundedProfile>,
    /// Per-manifest diagnostics for `META-INF/ASiCManifest*.xml` members.
    pub manifest_diagnostics: Vec<AsicManifestDiagnostic>,
    /// Per-signature diagnostics for recognised CAdES/XAdES signature members.
    pub signature_diagnostics: Vec<AsicSignatureDiagnostic>,
    /// Structured blockers with stable IDs.
    pub blocker_details: Vec<AsicDiagnosticBlocker>,
    /// Structural reasons this member shape cannot be handled by the bounded ASiC/CAdES parser.
    pub blockers: Vec<String>,
}

impl AsicProfileReport {
    /// Whether the member shape is one of the bounded ASiC/CAdES candidates. This still does not
    /// prove manifest digest binding or CAdES cryptographic validity.
    pub fn is_bounded_supported_candidate(&self) -> bool {
        self.bounded_profile.is_some() && self.blockers.is_empty()
    }
}

/// Compute the SHA-256 content digest used by detached CAdES-B validation.
pub fn sha256_content_digest(content: &[u8]) -> [u8; 32] {
    Sha256::digest(content).into()
}

/// Create a bounded ASiC-S container from one payload and an existing detached CAdES-B signature.
///
/// The emitted ZIP uses the ASiC-S `mimetype` member first and uncompressed, then the payload, then
/// `META-INF/signatures.p7s`. This is only a technical container around the supplied CAdES bytes.
pub fn create_asic_s_container(
    content_name: &str,
    content: &[u8],
    cades_signature_der: &[u8],
) -> Result<Vec<u8>, SigningError> {
    validate_payload_name(content_name)?;
    if cades_signature_der.is_empty() {
        return Err(asic_err("ASiC-S signatures.p7s cannot be empty"));
    }

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default());
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));

    zip.start_file(MIMETYPE_PATH, options)
        .map_err(|e| zip_err("failed to start ASiC mimetype member", e))?;
    zip.write_all(ASICS_MIMETYPE.as_bytes())
        .map_err(|e| asic_err(format!("failed to write ASiC mimetype member: {e}")))?;

    zip.start_file(content_name, options)
        .map_err(|e| zip_err("failed to start ASiC payload member", e))?;
    zip.write_all(content)
        .map_err(|e| asic_err(format!("failed to write ASiC payload member: {e}")))?;

    zip.start_file(ASICS_CADES_SIGNATURE_PATH, options)
        .map_err(|e| zip_err("failed to start ASiC CAdES signature member", e))?;
    zip.write_all(cades_signature_der)
        .map_err(|e| asic_err(format!("failed to write ASiC CAdES signature member: {e}")))?;

    zip.finish()
        .map(|cursor| cursor.into_inner())
        .map_err(|e| zip_err("failed to finish ASiC-S ZIP container", e))
}

/// Build the deterministic ASiC-E manifest bytes for the supplied payloads.
///
/// The manifest records one `SigReference` pointing at `signature_path` and one SHA-256
/// `DataObjectReference` per payload. The CAdES signature for a bounded ASiC-E/CAdES container
/// must cover these exact manifest bytes.
pub fn build_asic_e_manifest(
    payloads: &[AsicPayload<'_>],
    signature_path: &str,
) -> Result<Vec<u8>, SigningError> {
    validate_cades_signature_path(signature_path)?;
    validate_payloads(payloads)?;

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<asic:ASiCManifest xmlns:asic=\"{}\" xmlns:ds=\"{}\">\n",
        ASIC_NS, DS_NS
    ));
    xml.push_str(&format!(
        "  <asic:SigReference URI=\"{}\" MimeType=\"{}\"/>\n",
        escape_xml_attr(signature_path),
        CADES_SIGNATURE_MIME_TYPE
    ));

    for payload in payloads {
        let digest = sha256_content_digest(payload.bytes);
        let digest_b64 = BASE64_STANDARD.encode(digest);
        let mime = payload
            .mime_type
            .map(|mime_type| format!(" MimeType=\"{}\"", escape_xml_attr(mime_type)))
            .unwrap_or_default();
        xml.push_str(&format!(
            "  <asic:DataObjectReference URI=\"{}\"{}>\n",
            escape_xml_attr(payload.name),
            mime
        ));
        xml.push_str(&format!(
            "    <ds:DigestMethod Algorithm=\"{}\"/>\n",
            SHA256_DIGEST_METHOD_URI
        ));
        xml.push_str(&format!(
            "    <ds:DigestValue>{}</ds:DigestValue>\n",
            digest_b64
        ));
        xml.push_str("  </asic:DataObjectReference>\n");
    }

    xml.push_str("</asic:ASiCManifest>\n");
    Ok(xml.into_bytes())
}

/// Create a bounded ASiC-E/CAdES container from one or more payloads and an existing detached
/// CAdES-B signature over [`build_asic_e_manifest`] bytes.
///
/// The emitted ZIP uses the ASiC-E `mimetype` member first and uncompressed, then the payloads,
/// then `META-INF/ASiCManifest.xml`, then `META-INF/signature001.p7s`.
pub fn create_asic_e_container(
    payloads: &[AsicPayload<'_>],
    cades_signature_der: &[u8],
) -> Result<Vec<u8>, SigningError> {
    if cades_signature_der.is_empty() {
        return Err(asic_err("ASiC-E signature001.p7s cannot be empty"));
    }
    let manifest = build_asic_e_manifest(payloads, ASICE_CADES_SIGNATURE_PATH)?;

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default());
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));

    zip.start_file(MIMETYPE_PATH, options)
        .map_err(|e| zip_err("failed to start ASiC mimetype member", e))?;
    zip.write_all(ASICE_MIMETYPE.as_bytes())
        .map_err(|e| asic_err(format!("failed to write ASiC mimetype member: {e}")))?;

    for payload in payloads {
        zip.start_file(payload.name, options)
            .map_err(|e| zip_err("failed to start ASiC-E payload member", e))?;
        zip.write_all(payload.bytes)
            .map_err(|e| asic_err(format!("failed to write ASiC-E payload member: {e}")))?;
    }

    zip.start_file(ASICE_MANIFEST_PATH, options)
        .map_err(|e| zip_err("failed to start ASiC-E manifest member", e))?;
    zip.write_all(&manifest)
        .map_err(|e| asic_err(format!("failed to write ASiC-E manifest member: {e}")))?;

    zip.start_file(ASICE_CADES_SIGNATURE_PATH, options)
        .map_err(|e| zip_err("failed to start ASiC-E CAdES signature member", e))?;
    zip.write_all(cades_signature_der).map_err(|e| {
        asic_err(format!(
            "failed to write ASiC-E CAdES signature member: {e}"
        ))
    })?;

    zip.finish()
        .map(|cursor| cursor.into_inner())
        .map_err(|e| zip_err("failed to finish ASiC-E ZIP container", e))
}

/// A reference an archive manifest covers: a container member (payload, signature, or manifest)
/// protected by the archive timestamp.
#[derive(Debug, Clone, Copy)]
pub struct AsicArchiveReference<'a> {
    /// The member path referenced by the archive manifest.
    pub uri: &'a str,
    /// The referenced member's bytes (hashed for `DigestValue`).
    pub bytes: &'a [u8],
    /// Optional media type recorded on the `DataObjectReference`.
    pub mime_type: Option<&'a str>,
}

/// Create a bounded ASiC-S container carrying one payload and a detached XAdES signature over it.
///
/// The emitted ZIP uses the ASiC-S `mimetype` member first and uncompressed, then the payload, then
/// [`ASICS_XADES_SIGNATURE_PATH`]. The XAdES document must reference the single payload by its
/// member name (the caller builds it through [`crate::asic_sign::sign_asic_s_xades`]).
pub fn create_asic_s_xades_container(
    content_name: &str,
    content: &[u8],
    xades_signature_xml: &[u8],
) -> Result<Vec<u8>, SigningError> {
    validate_payload_name(content_name)?;
    if xades_signature_xml.is_empty() {
        return Err(asic_err("ASiC-S signatures.xml cannot be empty"));
    }

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default());
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));

    zip.start_file(MIMETYPE_PATH, options)
        .map_err(|e| zip_err("failed to start ASiC mimetype member", e))?;
    zip.write_all(ASICS_MIMETYPE.as_bytes())
        .map_err(|e| asic_err(format!("failed to write ASiC mimetype member: {e}")))?;

    zip.start_file(content_name, options)
        .map_err(|e| zip_err("failed to start ASiC payload member", e))?;
    zip.write_all(content)
        .map_err(|e| asic_err(format!("failed to write ASiC payload member: {e}")))?;

    zip.start_file(ASICS_XADES_SIGNATURE_PATH, options)
        .map_err(|e| zip_err("failed to start ASiC XAdES signature member", e))?;
    zip.write_all(xades_signature_xml)
        .map_err(|e| asic_err(format!("failed to write ASiC XAdES signature member: {e}")))?;

    zip.finish()
        .map(|cursor| cursor.into_inner())
        .map_err(|e| zip_err("failed to finish ASiC-S/XAdES ZIP container", e))
}

/// Assemble a general ASiC-E container from payloads plus already-produced `META-INF` members
/// (per-signature manifests, CAdES/XAdES signatures, archive manifest, and archive-timestamp token).
///
/// This is the multi-signature counterpart to [`create_asic_e_container`]: the caller has already
/// built and signed every `META-INF` member (see [`crate::asic_sign::sign_asic_e_multi`]); this
/// function only lays them out in a well-formed ZIP with the `mimetype` member first and stored.
/// Member names are validated but their internal structure is the caller's responsibility.
pub fn assemble_asic_e_container(
    payloads: &[AsicPayload<'_>],
    meta_inf_members: &[(&str, &[u8])],
) -> Result<Vec<u8>, SigningError> {
    validate_payloads(payloads)?;
    if meta_inf_members.is_empty() {
        return Err(asic_err(
            "ASiC-E container requires at least one META-INF signature member",
        ));
    }
    let mut seen = HashSet::new();
    for (name, bytes) in meta_inf_members {
        validate_member_name(name)?;
        if !is_meta_inf_path(name) {
            return Err(asic_err(format!(
                "ASiC-E signature member {name} must live under META-INF/"
            )));
        }
        if name.ends_with('/') {
            return Err(asic_err(format!(
                "ASiC-E META-INF member {name} must be a file"
            )));
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(asic_err(format!("duplicate ASiC-E META-INF member {name}")));
        }
        if bytes.is_empty() {
            return Err(asic_err(format!("ASiC-E META-INF member {name} is empty")));
        }
    }

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default());
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));

    zip.start_file(MIMETYPE_PATH, options)
        .map_err(|e| zip_err("failed to start ASiC mimetype member", e))?;
    zip.write_all(ASICE_MIMETYPE.as_bytes())
        .map_err(|e| asic_err(format!("failed to write ASiC mimetype member: {e}")))?;

    for payload in payloads {
        zip.start_file(payload.name, options)
            .map_err(|e| zip_err("failed to start ASiC-E payload member", e))?;
        zip.write_all(payload.bytes)
            .map_err(|e| asic_err(format!("failed to write ASiC-E payload member: {e}")))?;
    }

    for (name, bytes) in meta_inf_members {
        zip.start_file(*name, options)
            .map_err(|e| zip_err("failed to start ASiC-E META-INF member", e))?;
        zip.write_all(bytes)
            .map_err(|e| asic_err(format!("failed to write ASiC-E META-INF member: {e}")))?;
    }

    zip.finish()
        .map(|cursor| cursor.into_inner())
        .map_err(|e| zip_err("failed to finish ASiC-E ZIP container", e))
}

/// Build the deterministic ASiCArchiveManifest bytes covering `references` and pointing at the
/// RFC 3161 archive-timestamp token at `timestamp_path`.
///
/// The archive manifest records one `SigReference` to the timestamp token and one SHA-256
/// `DataObjectReference` per covered member (payloads, per-signature manifests, and signatures).
/// The archive timestamp is then taken over these exact manifest bytes.
pub fn build_asic_archive_manifest(
    timestamp_path: &str,
    references: &[AsicArchiveReference<'_>],
) -> Result<Vec<u8>, SigningError> {
    validate_member_name(timestamp_path)?;
    if !is_meta_inf_path(timestamp_path) || !timestamp_path.to_ascii_lowercase().ends_with(".tst") {
        return Err(asic_err(format!(
            "ASiC archive timestamp reference {timestamp_path} must be a META-INF/*.tst member"
        )));
    }
    if references.is_empty() {
        return Err(asic_err(
            "ASiC archive manifest must reference at least one member",
        ));
    }

    let mut seen = HashSet::new();
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<asic:ASiCManifest xmlns:asic=\"{ASIC_NS}\" xmlns:ds=\"{DS_NS}\">\n"
    ));
    xml.push_str(&format!(
        "  <asic:SigReference URI=\"{}\" MimeType=\"{}\"/>\n",
        escape_xml_attr(timestamp_path),
        RFC3161_TIMESTAMP_MIME_TYPE
    ));
    for reference in references {
        validate_member_name(reference.uri)?;
        if !seen.insert(reference.uri.to_ascii_lowercase()) {
            return Err(asic_err(format!(
                "duplicate ASiC archive manifest reference {}",
                reference.uri
            )));
        }
        let digest_b64 = BASE64_STANDARD.encode(sha256_content_digest(reference.bytes));
        let mime = reference
            .mime_type
            .map(|mime_type| format!(" MimeType=\"{}\"", escape_xml_attr(mime_type)))
            .unwrap_or_default();
        xml.push_str(&format!(
            "  <asic:DataObjectReference URI=\"{}\"{}>\n",
            escape_xml_attr(reference.uri),
            mime
        ));
        xml.push_str(&format!(
            "    <ds:DigestMethod Algorithm=\"{SHA256_DIGEST_METHOD_URI}\"/>\n"
        ));
        xml.push_str(&format!(
            "    <ds:DigestValue>{digest_b64}</ds:DigestValue>\n"
        ));
        xml.push_str("  </asic:DataObjectReference>\n");
    }
    xml.push_str("</asic:ASiCManifest>\n");
    Ok(xml.into_bytes())
}

/// Parse and validate either bounded ASiC shape implemented by this crate.
pub fn extract_asic_container(container: &[u8]) -> Result<AsicContainer, SigningError> {
    match detect_mimetype(container)? {
        AsicContainerKind::AsicS => extract_asic_s_container(container).map(AsicContainer::S),
        AsicContainerKind::AsicE => extract_asic_e_container(container).map(AsicContainer::E),
    }
}

/// Inspect ASiC ZIP structure and report the declared profile shape.
///
/// The report is meant for diagnostics and compliance evidence. It validates the strict ASiC
/// `mimetype` member placement/compression and safe member names, but it does not parse XAdES,
/// validate CAdES signatures, or prove ASiC-E manifest digest binding.
pub fn inspect_asic_profile(container: &[u8]) -> Result<AsicProfileReport, SigningError> {
    let mut archive = ZipArchive::new(Cursor::new(container))
        .map_err(|e| zip_err("ASiC container is not a readable ZIP archive", e))?;
    if archive.is_empty() {
        return Err(asic_err("ASiC container ZIP archive is empty"));
    }

    let container_kind = read_mimetype(&mut archive)?;
    let mut seen = HashSet::new();
    let mut member_names = Vec::with_capacity(archive.len());
    let mut payload_paths = Vec::new();
    let mut manifest_paths = Vec::new();
    let mut cades_signature_paths = Vec::new();
    let mut xades_signature_paths = Vec::new();
    let mut unsupported_meta_inf_paths = Vec::new();
    let mut payloads = HashMap::new();
    let mut manifest_members = Vec::new();
    let mut signature_diagnostics = Vec::new();
    let mut blocker_details = Vec::new();
    let mut size_budget = ZipSizeBudget::default();

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|e| zip_err("failed to read ASiC ZIP member", e))?;
        let name = file.name().to_owned();
        validate_member_name(&name)?;
        if !seen.insert(name.clone()) {
            push_blocker(
                &mut blocker_details,
                AsicDiagnosticBlockerId::DuplicateMember,
                format!("duplicate ASiC ZIP member {name}"),
                Some(name.clone()),
            );
        }
        let encrypted = file.encrypted();
        if encrypted {
            push_blocker(
                &mut blocker_details,
                AsicDiagnosticBlockerId::EncryptedMember,
                format!("encrypted ASiC ZIP member {name} is not supported"),
                Some(name.clone()),
            );
        }
        let size = file.size();
        let size_inspection =
            size_budget.inspect_declared_preflight(&name, size, &mut blocker_details);
        let read_allowed = size_inspection.read_allowed && !encrypted;
        let size_blockers = size_inspection.blockers;
        member_names.push(name.clone());
        if file.is_dir() || name == MIMETYPE_PATH {
            continue;
        }

        if is_xades_signature_path(&name) {
            xades_signature_paths.push(name.clone());
            let mut signature_blockers = size_blockers;
            let diagnostic_size = if read_allowed {
                let (actual_size, actual_size_inspection) = account_zip_member_for_inspection(
                    &name,
                    &mut file,
                    &mut size_budget,
                    &mut blocker_details,
                )?;
                signature_blockers.extend(actual_size_inspection.blockers);
                actual_size
            } else {
                size
            };
            signature_diagnostics.push(AsicSignatureDiagnostic {
                path: name,
                member_kind: AsicSignatureMemberKind::Xades,
                size: diagnostic_size,
                referenced_by_manifest_paths: Vec::new(),
                blockers: signature_blockers,
            });
        } else if is_asic_manifest_path(&name) {
            manifest_paths.push(name.clone());
            if read_allowed {
                let bytes = read_zip_member_for_inspection(&name, &mut file, size)?;
                let actual_size = bytes.len() as u64;
                let actual_size_inspection =
                    size_budget.inspect_actual_consumed(&name, actual_size, &mut blocker_details);
                if actual_size_inspection.read_allowed {
                    manifest_members.push((name, bytes, actual_size));
                }
            }
        } else if is_meta_inf_path(&name) {
            if is_cades_signature_path(&name) {
                cades_signature_paths.push(name.clone());
                let mut signature_blockers = size_blockers;
                let diagnostic_size = if read_allowed {
                    let (actual_size, actual_size_inspection) = account_zip_member_for_inspection(
                        &name,
                        &mut file,
                        &mut size_budget,
                        &mut blocker_details,
                    )?;
                    signature_blockers.extend(actual_size_inspection.blockers);
                    actual_size
                } else {
                    size
                };
                if diagnostic_size == 0 {
                    let blocker = diagnostic_blocker(
                        AsicDiagnosticBlockerId::EmptySignatureMember,
                        format!("ASiC CAdES signature member {name} is empty"),
                        Some(name.clone()),
                    );
                    blocker_details.push(blocker.clone());
                    signature_blockers.push(blocker);
                }
                signature_diagnostics.push(AsicSignatureDiagnostic {
                    path: name,
                    member_kind: AsicSignatureMemberKind::Cades,
                    size: diagnostic_size,
                    referenced_by_manifest_paths: Vec::new(),
                    blockers: signature_blockers,
                });
            } else {
                unsupported_meta_inf_paths.push(name.clone());
                if read_allowed {
                    let _ = account_zip_member_for_inspection(
                        &name,
                        &mut file,
                        &mut size_budget,
                        &mut blocker_details,
                    )?;
                }
            }
        } else {
            payload_paths.push(name.clone());
            if read_allowed {
                let bytes = read_zip_member_for_inspection(&name, &mut file, size)?;
                let actual_size_inspection = size_budget.inspect_actual_consumed(
                    &name,
                    bytes.len() as u64,
                    &mut blocker_details,
                );
                if actual_size_inspection.read_allowed {
                    payloads.insert(name.clone(), bytes);
                }
            }
        }
    }

    let signature_profile = match (
        cades_signature_paths.is_empty(),
        xades_signature_paths.is_empty(),
    ) {
        (false, false) => AsicSignatureProfile::Mixed,
        (false, true) => AsicSignatureProfile::Cades,
        (true, false) => AsicSignatureProfile::Xades,
        (true, true) => AsicSignatureProfile::Unsigned,
    };

    append_profile_blockers(
        container_kind,
        &payload_paths,
        &manifest_paths,
        &cades_signature_paths,
        &xades_signature_paths,
        &unsupported_meta_inf_paths,
        &mut blocker_details,
    );
    let bounded_profile = bounded_profile(
        container_kind,
        &payload_paths,
        &manifest_paths,
        &cades_signature_paths,
    );
    let mut manifest_diagnostics = build_manifest_diagnostics(
        container_kind,
        &manifest_members,
        &payloads,
        &signature_diagnostics,
        &mut blocker_details,
    );
    link_signature_manifest_references(&mut signature_diagnostics, &manifest_diagnostics);
    append_unreferenced_signature_blockers(
        container_kind,
        &manifest_diagnostics,
        &mut signature_diagnostics,
        &mut blocker_details,
    );
    append_manifest_unreferenced_payload_blockers(
        container_kind,
        &payload_paths,
        &mut manifest_diagnostics,
        &mut blocker_details,
    );
    let profile_shape = profile_shape(container_kind, signature_profile, bounded_profile);
    let blockers = blocker_details
        .iter()
        .map(|blocker| blocker.message.clone())
        .collect();

    Ok(AsicProfileReport {
        container_kind,
        mimetype: container_kind.mimetype(),
        member_names,
        payload_paths,
        manifest_paths,
        cades_signature_paths,
        xades_signature_paths,
        unsupported_meta_inf_paths,
        signature_profile,
        profile_shape,
        bounded_profile,
        manifest_diagnostics,
        signature_diagnostics,
        blocker_details,
        blockers,
    })
}

/// Parse and validate the bounded ASiC-S/CAdES container shape.
///
/// This function verifies only the container structure. The caller must still validate
/// `cades_signature_der` against `sha256_content_digest(content)`.
pub fn extract_asic_s_container(container: &[u8]) -> Result<AsicSContainer, SigningError> {
    let mut archive = ZipArchive::new(Cursor::new(container))
        .map_err(|e| zip_err("ASiC container is not a readable ZIP archive", e))?;
    if archive.is_empty() {
        return Err(asic_err("ASiC container ZIP archive is empty"));
    }

    read_and_check_mimetype(&mut archive)?;

    let mut seen = HashSet::new();
    let mut content: Option<(String, Vec<u8>)> = None;
    let mut cades_signature_der: Option<Vec<u8>> = None;
    let mut xades_signature_paths = Vec::new();
    let mut size_budget = ZipSizeBudget::default();

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|e| zip_err("failed to read ASiC ZIP member", e))?;
        let name = file.name().to_owned();
        validate_member_name(&name)?;
        if !seen.insert(name.clone()) {
            return Err(asic_err(format!("duplicate ASiC ZIP member {name}")));
        }
        if file.encrypted() {
            return Err(asic_err(format!(
                "encrypted ASiC ZIP member {name} is not supported"
            )));
        }
        let size = file.size();
        size_budget.enforce_declared_preflight(&name, size)?;
        if file.is_dir() {
            continue;
        }

        if name == MIMETYPE_PATH {
            continue;
        }
        if name == ASICS_CADES_SIGNATURE_PATH {
            let bytes = read_zip_member(&name, &mut file, size)?;
            size_budget.enforce_actual_consumed(&name, bytes.len() as u64)?;
            if bytes.is_empty() {
                return Err(asic_err("ASiC-S signatures.p7s cannot be empty"));
            }
            cades_signature_der = Some(bytes);
            continue;
        }
        if is_xades_signature_path(&name) {
            xades_signature_paths.push(name);
            continue;
        }
        if is_meta_inf_path(&name) {
            return Err(asic_err(format!(
                "unsupported ASiC META-INF member {name}; only META-INF/signatures.p7s is implemented"
            )));
        }

        if content.is_some() {
            return Err(asic_err(
                "ASiC-E or multi-payload ASiC containers are not supported; only one ASiC-S payload is implemented",
            ));
        }
        let bytes = read_zip_member(&name, &mut file, size)?;
        size_budget.enforce_actual_consumed(&name, bytes.len() as u64)?;
        content = Some((name, bytes));
    }

    if !xades_signature_paths.is_empty() {
        return Err(unsupported_asic_xades_error(
            AsicContainerKind::AsicS,
            &xades_signature_paths,
        ));
    }

    let cades_signature_der = cades_signature_der.ok_or_else(|| {
        asic_err("ASiC-S container is missing META-INF/signatures.p7s detached CAdES signature")
    })?;
    let (content_name, content) = content.ok_or_else(|| {
        asic_err("ASiC-S container is missing the single payload signed by signatures.p7s")
    })?;

    Ok(AsicSContainer {
        content_name,
        content,
        cades_signature_der,
    })
}

/// Parse and validate the bounded ASiC-E/CAdES container shape.
///
/// This verifies the ZIP structure, one `ASiCManifest` file, one referenced CAdES signature file,
/// and every manifest payload digest. The caller must still validate `cades_signature_der` against
/// `sha256_content_digest(manifest)`.
pub fn extract_asic_e_container(container: &[u8]) -> Result<AsicEContainer, SigningError> {
    let mut archive = ZipArchive::new(Cursor::new(container))
        .map_err(|e| zip_err("ASiC container is not a readable ZIP archive", e))?;
    if archive.is_empty() {
        return Err(asic_err("ASiC container ZIP archive is empty"));
    }

    read_and_check_asice_mimetype(&mut archive)?;

    let mut seen = HashSet::new();
    let mut payloads: HashMap<String, Vec<u8>> = HashMap::new();
    let mut meta_inf_files: HashMap<String, Vec<u8>> = HashMap::new();
    let mut manifest: Option<(String, Vec<u8>)> = None;
    let mut xades_signature_paths = Vec::new();
    let mut size_budget = ZipSizeBudget::default();

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|e| zip_err("failed to read ASiC ZIP member", e))?;
        let name = file.name().to_owned();
        validate_member_name(&name)?;
        if !seen.insert(name.clone()) {
            return Err(asic_err(format!("duplicate ASiC ZIP member {name}")));
        }
        if file.encrypted() {
            return Err(asic_err(format!(
                "encrypted ASiC ZIP member {name} is not supported"
            )));
        }
        let size = file.size();
        size_budget.enforce_declared_preflight(&name, size)?;
        if file.is_dir() {
            continue;
        }

        if name == MIMETYPE_PATH {
            continue;
        }
        if is_xades_signature_path(&name) {
            xades_signature_paths.push(name);
            continue;
        }
        if is_asic_manifest_path(&name) {
            if manifest.is_some() {
                return Err(asic_err(
                    "multiple ASiC-E ASiCManifest files are not supported",
                ));
            }
            let bytes = read_zip_member(&name, &mut file, size)?;
            size_budget.enforce_actual_consumed(&name, bytes.len() as u64)?;
            if bytes.is_empty() {
                return Err(asic_err("ASiC-E ASiCManifest file cannot be empty"));
            }
            manifest = Some((name, bytes));
            continue;
        }
        if is_meta_inf_path(&name) {
            if !is_cades_signature_path(&name) {
                return Err(asic_err(format!(
                    "unsupported ASiC-E META-INF member {name}; only ASiCManifest XML and CAdES .p7s signature files are implemented"
                )));
            }
            let bytes = read_zip_member(&name, &mut file, size)?;
            size_budget.enforce_actual_consumed(&name, bytes.len() as u64)?;
            if bytes.is_empty() {
                return Err(asic_err(format!(
                    "ASiC-E CAdES signature member {name} is empty"
                )));
            }
            meta_inf_files.insert(name, bytes);
            continue;
        }

        validate_payload_name(&name)?;
        let bytes = read_zip_member(&name, &mut file, size)?;
        size_budget.enforce_actual_consumed(&name, bytes.len() as u64)?;
        payloads.insert(name.clone(), bytes);
    }

    if !xades_signature_paths.is_empty() {
        return Err(unsupported_asic_xades_error(
            AsicContainerKind::AsicE,
            &xades_signature_paths,
        ));
    }
    if payloads.is_empty() {
        return Err(asic_err("ASiC-E container is missing payload data objects"));
    }

    let (manifest_path, manifest_bytes) = manifest
        .ok_or_else(|| asic_err("ASiC-E/CAdES container is missing META-INF/ASiCManifest*.xml"))?;
    if manifest_path != ASICE_MANIFEST_PATH {
        return Err(asic_err(format!(
            "unsupported ASiC-E manifest member {manifest_path}; only {ASICE_MANIFEST_PATH} is implemented"
        )));
    }

    let parsed = parse_asic_e_manifest(&manifest_bytes)?;
    validate_cades_signature_path(&parsed.signature_path)?;
    let cades_signature_der = meta_inf_files
        .remove(&parsed.signature_path)
        .ok_or_else(|| {
            asic_err(format!(
                "ASiC-E manifest references missing CAdES signature {}",
                parsed.signature_path
            ))
        })?;
    if !meta_inf_files.is_empty() {
        let mut extra: Vec<_> = meta_inf_files.into_keys().collect();
        extra.sort();
        return Err(asic_err(format!(
            "unsupported additional ASiC-E CAdES signature members: {}",
            extra.join(", ")
        )));
    }

    let mut referenced = HashSet::new();
    let mut data_objects = Vec::with_capacity(parsed.data_objects.len());
    for data_object in parsed.data_objects {
        validate_payload_name(&data_object.name)?;
        if !referenced.insert(data_object.name.clone()) {
            return Err(asic_err(format!(
                "duplicate ASiC-E manifest payload reference {}",
                data_object.name
            )));
        }
        let bytes = payloads.get(&data_object.name).ok_or_else(|| {
            asic_err(format!(
                "ASiC-E manifest references missing payload {}",
                data_object.name
            ))
        })?;
        let actual_digest = sha256_content_digest(bytes);
        if actual_digest != data_object.sha256_digest {
            return Err(asic_err(format!(
                "ASiC-E manifest digest mismatch for payload {}",
                data_object.name
            )));
        }
        data_objects.push(AsicEDataObject {
            name: data_object.name,
            bytes: bytes.clone(),
            mime_type: data_object.mime_type,
            sha256_digest: actual_digest,
        });
    }

    let mut unreferenced: Vec<_> = payloads
        .keys()
        .filter(|name| !referenced.contains(*name))
        .cloned()
        .collect();
    if !unreferenced.is_empty() {
        unreferenced.sort();
        return Err(asic_err(format!(
            "ASiC-E payloads missing from manifest: {}",
            unreferenced.join(", ")
        )));
    }

    Ok(AsicEContainer {
        manifest: manifest_bytes,
        signature_path: parsed.signature_path,
        cades_signature_der,
        data_objects,
    })
}

fn detect_mimetype(container: &[u8]) -> Result<AsicContainerKind, SigningError> {
    let mut archive = ZipArchive::new(Cursor::new(container))
        .map_err(|e| zip_err("ASiC container is not a readable ZIP archive", e))?;
    if archive.is_empty() {
        return Err(asic_err("ASiC container ZIP archive is empty"));
    }
    read_mimetype(&mut archive)
}

fn read_and_check_mimetype(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Result<(), SigningError> {
    match read_mimetype(archive)? {
        AsicContainerKind::AsicS => Ok(()),
        AsicContainerKind::AsicE => Err(asic_err(
            "ASiC-E containers must be parsed through the ASiC-E/CAdES manifest path",
        )),
    }
}

fn read_and_check_asice_mimetype(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
) -> Result<(), SigningError> {
    match read_mimetype(archive)? {
        AsicContainerKind::AsicE => Ok(()),
        AsicContainerKind::AsicS => Err(asic_err(
            "ASiC-S containers must be parsed through the ASiC-S/CAdES path",
        )),
    }
}

fn read_mimetype(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
) -> Result<AsicContainerKind, SigningError> {
    let mut first = archive
        .by_index(0)
        .map_err(|e| zip_err("failed to read first ASiC ZIP member", e))?;
    let name = first.name().to_owned();
    validate_member_name(&name)?;
    if name != MIMETYPE_PATH {
        return Err(asic_err(format!(
            "ASiC requires the first ZIP member to be mimetype, got {name}"
        )));
    }
    if first.encrypted() {
        return Err(asic_err("ASiC mimetype member must not be encrypted"));
    }
    if first.compression() != CompressionMethod::Stored {
        return Err(asic_err(
            "ASiC mimetype member must be stored without compression",
        ));
    }
    check_zip_member_uncompressed_size(&name, first.size(), ZipSizeObservation::Declared)?;
    let mut mimetype = String::new();
    first
        .read_to_string(&mut mimetype)
        .map_err(|e| asic_err(format!("failed to read ASiC mimetype member: {e}")))?;

    match mimetype.as_str() {
        ASICS_MIMETYPE => Ok(AsicContainerKind::AsicS),
        ASICE_MIMETYPE => Ok(AsicContainerKind::AsicE),
        other => Err(asic_err(format!(
            "unsupported ASiC mimetype {other}; expected {ASICS_MIMETYPE} or {ASICE_MIMETYPE}"
        ))),
    }
}

fn diagnostic_blocker(
    id: AsicDiagnosticBlockerId,
    message: impl Into<String>,
    member_path: Option<String>,
) -> AsicDiagnosticBlocker {
    AsicDiagnosticBlocker {
        id,
        message: message.into(),
        member_path,
    }
}

fn push_blocker(
    blockers: &mut Vec<AsicDiagnosticBlocker>,
    id: AsicDiagnosticBlockerId,
    message: impl Into<String>,
    member_path: Option<String>,
) {
    blockers.push(diagnostic_blocker(id, message, member_path));
}

#[derive(Debug, Default)]
struct ZipSizeBudget {
    actual_uncompressed_size: u64,
    total_limit_exceeded: bool,
}

#[derive(Debug)]
struct ZipMemberSizeInspection {
    read_allowed: bool,
    blockers: Vec<AsicDiagnosticBlocker>,
}

impl ZipSizeBudget {
    fn enforce_declared_preflight(
        &self,
        name: &str,
        declared_size: u64,
    ) -> Result<(), SigningError> {
        check_zip_member_uncompressed_size(name, declared_size, ZipSizeObservation::Declared)?;
        if self.total_limit_exceeded {
            return Err(zip_total_uncompressed_size_error(
                name,
                self.actual_uncompressed_size,
                ZipSizeObservation::Actual,
            ));
        }
        let predicted_total = self.actual_uncompressed_size.saturating_add(declared_size);
        if predicted_total > ASIC_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES {
            return Err(zip_total_uncompressed_size_error(
                name,
                predicted_total,
                ZipSizeObservation::Declared,
            ));
        }
        Ok(())
    }

    fn enforce_actual_consumed(
        &mut self,
        name: &str,
        actual_size: u64,
    ) -> Result<(), SigningError> {
        check_zip_member_uncompressed_size(name, actual_size, ZipSizeObservation::Actual)?;
        let total = self.actual_uncompressed_size.saturating_add(actual_size);
        self.actual_uncompressed_size = total;
        if total > ASIC_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES {
            self.total_limit_exceeded = true;
            return Err(zip_total_uncompressed_size_error(
                name,
                total,
                ZipSizeObservation::Actual,
            ));
        }
        Ok(())
    }

    fn inspect_declared_preflight(
        &mut self,
        name: &str,
        declared_size: u64,
        global_blockers: &mut Vec<AsicDiagnosticBlocker>,
    ) -> ZipMemberSizeInspection {
        let mut blockers = Vec::new();
        let member_within_limit = if declared_size > ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES {
            let blocker = diagnostic_blocker(
                AsicDiagnosticBlockerId::MemberUncompressedSizeExceeded,
                zip_member_uncompressed_size_message(
                    name,
                    declared_size,
                    ZipSizeObservation::Declared,
                ),
                Some(name.to_owned()),
            );
            global_blockers.push(blocker.clone());
            blockers.push(blocker);
            false
        } else {
            true
        };

        let total_within_limit = if self.total_limit_exceeded {
            false
        } else {
            let predicted_total = self.actual_uncompressed_size.saturating_add(declared_size);
            if predicted_total > ASIC_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES {
                self.total_limit_exceeded = true;
                let blocker = diagnostic_blocker(
                    AsicDiagnosticBlockerId::TotalUncompressedSizeExceeded,
                    zip_total_uncompressed_size_message(
                        name,
                        predicted_total,
                        ZipSizeObservation::Declared,
                    ),
                    Some(name.to_owned()),
                );
                global_blockers.push(blocker.clone());
                blockers.push(blocker);
                false
            } else {
                true
            }
        };

        ZipMemberSizeInspection {
            read_allowed: member_within_limit && total_within_limit,
            blockers,
        }
    }

    fn inspect_actual_consumed(
        &mut self,
        name: &str,
        actual_size: u64,
        global_blockers: &mut Vec<AsicDiagnosticBlocker>,
    ) -> ZipMemberSizeInspection {
        let mut blockers = Vec::new();
        let member_within_limit = if actual_size > ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES {
            let blocker = diagnostic_blocker(
                AsicDiagnosticBlockerId::MemberUncompressedSizeExceeded,
                zip_member_uncompressed_size_message(name, actual_size, ZipSizeObservation::Actual),
                Some(name.to_owned()),
            );
            global_blockers.push(blocker.clone());
            blockers.push(blocker);
            false
        } else {
            true
        };

        let total_within_limit = if self.total_limit_exceeded {
            false
        } else {
            let total = self.actual_uncompressed_size.saturating_add(actual_size);
            self.actual_uncompressed_size = total;
            if total > ASIC_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES {
                self.total_limit_exceeded = true;
                let blocker = diagnostic_blocker(
                    AsicDiagnosticBlockerId::TotalUncompressedSizeExceeded,
                    zip_total_uncompressed_size_message(name, total, ZipSizeObservation::Actual),
                    Some(name.to_owned()),
                );
                global_blockers.push(blocker.clone());
                blockers.push(blocker);
                false
            } else {
                true
            }
        };

        ZipMemberSizeInspection {
            read_allowed: member_within_limit && total_within_limit,
            blockers,
        }
    }
}

fn profile_shape(
    container_kind: AsicContainerKind,
    signature_profile: AsicSignatureProfile,
    bounded_profile: Option<AsicBoundedProfile>,
) -> AsicProfileShape {
    match (container_kind, signature_profile, bounded_profile) {
        (
            AsicContainerKind::AsicS,
            AsicSignatureProfile::Cades,
            Some(AsicBoundedProfile::AsicSCadesSinglePayload),
        ) => AsicProfileShape::AsicSCadesSinglePayload,
        (
            AsicContainerKind::AsicE,
            AsicSignatureProfile::Cades,
            Some(AsicBoundedProfile::AsicECadesSingleManifest),
        ) => AsicProfileShape::AsicECadesSingleManifest,
        (AsicContainerKind::AsicS, AsicSignatureProfile::Cades, _) => {
            AsicProfileShape::AsicSCadesUnsupported
        }
        (AsicContainerKind::AsicS, AsicSignatureProfile::Xades, _) => AsicProfileShape::AsicSXades,
        (AsicContainerKind::AsicS, AsicSignatureProfile::Mixed, _) => AsicProfileShape::AsicSMixed,
        (AsicContainerKind::AsicS, AsicSignatureProfile::Unsigned, _) => {
            AsicProfileShape::AsicSUnsigned
        }
        (AsicContainerKind::AsicE, AsicSignatureProfile::Cades, _) => {
            AsicProfileShape::AsicECadesUnsupported
        }
        (AsicContainerKind::AsicE, AsicSignatureProfile::Xades, _) => AsicProfileShape::AsicEXades,
        (AsicContainerKind::AsicE, AsicSignatureProfile::Mixed, _) => AsicProfileShape::AsicEMixed,
        (AsicContainerKind::AsicE, AsicSignatureProfile::Unsigned, _) => {
            AsicProfileShape::AsicEUnsigned
        }
    }
}

fn build_manifest_diagnostics(
    container_kind: AsicContainerKind,
    manifest_members: &[(String, Vec<u8>, u64)],
    payloads: &HashMap<String, Vec<u8>>,
    signature_diagnostics: &[AsicSignatureDiagnostic],
    global_blockers: &mut Vec<AsicDiagnosticBlocker>,
) -> Vec<AsicManifestDiagnostic> {
    let signature_kinds = signature_diagnostics
        .iter()
        .map(|signature| (signature.path.as_str(), signature.member_kind))
        .collect::<HashMap<_, _>>();
    let mut diagnostics = Vec::with_capacity(manifest_members.len());

    for (path, bytes, size) in manifest_members {
        let mut blockers = Vec::new();
        let mut signature_references = Vec::new();
        let mut data_object_references = Vec::new();

        if *size == 0 {
            let blocker = diagnostic_blocker(
                AsicDiagnosticBlockerId::EmptyManifestMember,
                format!("ASiC-E ASiCManifest member {path} is empty"),
                Some(path.clone()),
            );
            global_blockers.push(blocker.clone());
            blockers.push(blocker);
        } else if container_kind == AsicContainerKind::AsicE {
            match parse_asic_e_manifest(bytes) {
                Ok(parsed) => {
                    let member_kind = signature_kinds.get(parsed.signature_path.as_str()).copied();
                    let member_present = member_kind.is_some();
                    signature_references.push(AsicManifestSignatureReferenceDiagnostic {
                        uri: parsed.signature_path.clone(),
                        member_present,
                        member_kind,
                    });
                    if !member_present {
                        let blocker = diagnostic_blocker(
                            AsicDiagnosticBlockerId::AsicEManifestReferencesMissingSignature,
                            format!(
                                "ASiC-E manifest {path} references missing signature {}",
                                parsed.signature_path
                            ),
                            Some(path.clone()),
                        );
                        global_blockers.push(blocker.clone());
                        blockers.push(blocker);
                    }

                    for data_object in parsed.data_objects {
                        let actual_digest = payloads
                            .get(&data_object.name)
                            .map(|bytes| sha256_content_digest(bytes));
                        let digest_matches =
                            actual_digest.map(|actual| actual == data_object.sha256_digest);
                        data_object_references.push(AsicManifestDataObjectDiagnostic {
                            uri: data_object.name.clone(),
                            mime_type: data_object.mime_type,
                            payload_present: actual_digest.is_some(),
                            sha256_digest: data_object.sha256_digest,
                            digest_matches,
                        });

                        match digest_matches {
                            None => {
                                let blocker = diagnostic_blocker(
                                    AsicDiagnosticBlockerId::AsicEManifestReferencesMissingPayload,
                                    format!(
                                        "ASiC-E manifest {path} references missing payload {}",
                                        data_object.name
                                    ),
                                    Some(path.clone()),
                                );
                                global_blockers.push(blocker.clone());
                                blockers.push(blocker);
                            }
                            Some(false) => {
                                let blocker = diagnostic_blocker(
                                    AsicDiagnosticBlockerId::AsicEManifestDigestMismatch,
                                    format!(
                                        "ASiC-E manifest {path} digest mismatch for payload {}",
                                        data_object.name
                                    ),
                                    Some(path.clone()),
                                );
                                global_blockers.push(blocker.clone());
                                blockers.push(blocker);
                            }
                            Some(true) => {}
                        }
                    }
                }
                Err(err) => {
                    let blocker = diagnostic_blocker(
                        AsicDiagnosticBlockerId::AsicEManifestParseFailed,
                        format!(
                            "ASiC-E manifest {path} cannot be parsed by this bounded diagnostic reader: {}",
                            signing_error_message(&err)
                        ),
                        Some(path.clone()),
                    );
                    global_blockers.push(blocker.clone());
                    blockers.push(blocker);
                }
            }
        }

        diagnostics.push(AsicManifestDiagnostic {
            path: path.clone(),
            size: *size,
            signature_references,
            data_object_references,
            blockers,
        });
    }

    diagnostics
}

fn link_signature_manifest_references(
    signature_diagnostics: &mut [AsicSignatureDiagnostic],
    manifest_diagnostics: &[AsicManifestDiagnostic],
) {
    let mut references: HashMap<&str, Vec<String>> = HashMap::new();
    for manifest in manifest_diagnostics {
        for reference in &manifest.signature_references {
            references
                .entry(reference.uri.as_str())
                .or_default()
                .push(manifest.path.clone());
        }
    }

    for signature in signature_diagnostics {
        if let Some(manifest_paths) = references.get(signature.path.as_str()) {
            signature.referenced_by_manifest_paths = manifest_paths.clone();
        }
    }
}

fn append_unreferenced_signature_blockers(
    container_kind: AsicContainerKind,
    manifest_diagnostics: &[AsicManifestDiagnostic],
    signature_diagnostics: &mut [AsicSignatureDiagnostic],
    global_blockers: &mut Vec<AsicDiagnosticBlocker>,
) {
    if container_kind != AsicContainerKind::AsicE {
        return;
    }

    let referenced_signatures = manifest_diagnostics
        .iter()
        .flat_map(|manifest| manifest.signature_references.iter())
        .map(|reference| reference.uri.as_str())
        .collect::<HashSet<_>>();
    if referenced_signatures.is_empty() {
        return;
    }

    for signature in signature_diagnostics {
        if signature.member_kind == AsicSignatureMemberKind::Cades
            && !referenced_signatures.contains(signature.path.as_str())
        {
            let blocker = diagnostic_blocker(
                AsicDiagnosticBlockerId::AsicEUnreferencedSignature,
                format!(
                    "ASiC-E CAdES signature member {} is not referenced by the parsed manifest",
                    signature.path
                ),
                Some(signature.path.clone()),
            );
            global_blockers.push(blocker.clone());
            signature.blockers.push(blocker);
        }
    }
}

fn append_manifest_unreferenced_payload_blockers(
    container_kind: AsicContainerKind,
    payload_paths: &[String],
    manifest_diagnostics: &mut [AsicManifestDiagnostic],
    global_blockers: &mut Vec<AsicDiagnosticBlocker>,
) {
    if container_kind != AsicContainerKind::AsicE || manifest_diagnostics.len() != 1 {
        return;
    }
    let manifest = &mut manifest_diagnostics[0];
    if manifest.data_object_references.is_empty() {
        return;
    }

    let referenced_payloads = manifest
        .data_object_references
        .iter()
        .map(|reference| reference.uri.as_str())
        .collect::<HashSet<_>>();

    for payload_path in payload_paths {
        if !referenced_payloads.contains(payload_path.as_str()) {
            let blocker = diagnostic_blocker(
                AsicDiagnosticBlockerId::AsicEManifestUnreferencedPayload,
                format!(
                    "ASiC-E payload {payload_path} is not referenced by manifest {}",
                    manifest.path
                ),
                Some(manifest.path.clone()),
            );
            global_blockers.push(blocker.clone());
            manifest.blockers.push(blocker);
        }
    }
}

fn signing_error_message(err: &SigningError) -> String {
    match err {
        SigningError::Asic(message) => message.clone(),
        _ => err.to_string(),
    }
}

fn append_profile_blockers(
    container_kind: AsicContainerKind,
    payload_paths: &[String],
    manifest_paths: &[String],
    cades_signature_paths: &[String],
    xades_signature_paths: &[String],
    unsupported_meta_inf_paths: &[String],
    blockers: &mut Vec<AsicDiagnosticBlocker>,
) {
    if !xades_signature_paths.is_empty() {
        push_blocker(
            blockers,
            AsicDiagnosticBlockerId::XadesNotSupported,
            format!(
                "{} XAdES XML signature members are not implemented: {}",
                container_kind.label(),
                xades_signature_paths.join(", ")
            ),
            None,
        );
    }
    if !unsupported_meta_inf_paths.is_empty() {
        push_blocker(
            blockers,
            AsicDiagnosticBlockerId::UnsupportedMetaInfMember,
            format!(
                "{} contains unsupported META-INF members: {}",
                container_kind.label(),
                unsupported_meta_inf_paths.join(", ")
            ),
            None,
        );
    }

    match container_kind {
        AsicContainerKind::AsicS => {
            if payload_paths.len() != 1 {
                push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicSRequiresSinglePayload,
                    format!(
                        "ASiC-S/CAdES requires exactly one payload; found {}",
                        payload_paths.len()
                    ),
                    None,
                );
            }
            if !manifest_paths.is_empty() {
                push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicSManifestUnsupported,
                    format!(
                        "ASiC-S/CAdES does not use ASiCManifest members: {}",
                        manifest_paths.join(", ")
                    ),
                    None,
                );
            }
            match cades_signature_paths {
                [] => push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicSMissingCadesSignature,
                    format!("ASiC-S/CAdES requires {ASICS_CADES_SIGNATURE_PATH}"),
                    None,
                ),
                [path] if path.as_str() == ASICS_CADES_SIGNATURE_PATH => {}
                _ => push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicSUnsupportedCadesSignaturePath,
                    format!(
                        "ASiC-S/CAdES supports only {ASICS_CADES_SIGNATURE_PATH}; found {}",
                        cades_signature_paths.join(", ")
                    ),
                    None,
                ),
            }
        }
        AsicContainerKind::AsicE => {
            if payload_paths.is_empty() {
                push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicERequiresPayload,
                    "ASiC-E/CAdES requires at least one payload",
                    None,
                );
            }
            match manifest_paths {
                [] => push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicEMissingManifest,
                    format!("ASiC-E/CAdES requires {ASICE_MANIFEST_PATH}"),
                    None,
                ),
                [path] if path.as_str() == ASICE_MANIFEST_PATH => {}
                [path] => push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicEUnsupportedManifestPath,
                    format!("ASiC-E/CAdES supports only {ASICE_MANIFEST_PATH}; found {path}"),
                    Some(path.clone()),
                ),
                _ => push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicEMultipleManifests,
                    format!(
                        "ASiC-E/CAdES supports one ASiCManifest; found {}",
                        manifest_paths.join(", ")
                    ),
                    None,
                ),
            }
            match cades_signature_paths {
                [] => push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicEMissingCadesSignature,
                    "ASiC-E/CAdES requires one META-INF/*signature*.p7s member",
                    None,
                ),
                [_] => {}
                _ => push_blocker(
                    blockers,
                    AsicDiagnosticBlockerId::AsicEMultipleCadesSignatures,
                    format!(
                        "ASiC-E/CAdES supports one CAdES signature member; found {}",
                        cades_signature_paths.join(", ")
                    ),
                    None,
                ),
            }
        }
    }
}

fn bounded_profile(
    container_kind: AsicContainerKind,
    payload_paths: &[String],
    manifest_paths: &[String],
    cades_signature_paths: &[String],
) -> Option<AsicBoundedProfile> {
    match container_kind {
        AsicContainerKind::AsicS
            if payload_paths.len() == 1
                && manifest_paths.is_empty()
                && cades_signature_paths.len() == 1
                && cades_signature_paths[0] == ASICS_CADES_SIGNATURE_PATH =>
        {
            Some(AsicBoundedProfile::AsicSCadesSinglePayload)
        }
        AsicContainerKind::AsicE
            if !payload_paths.is_empty()
                && manifest_paths.len() == 1
                && manifest_paths[0] == ASICE_MANIFEST_PATH
                && cades_signature_paths.len() == 1 =>
        {
            Some(AsicBoundedProfile::AsicECadesSingleManifest)
        }
        _ => None,
    }
}

fn unsupported_asic_xades_error(
    container_kind: AsicContainerKind,
    xades_signature_paths: &[String],
) -> SigningError {
    let evidence = std::iter::once(format!("container_kind={}", container_kind.label()))
        .chain(
            xades_signature_paths
                .iter()
                .map(|path| format!("xades_signature_path={path}")),
        )
        .collect::<Vec<_>>();

    SigningError::UnsupportedProfile(
        UnsupportedSignatureProfile::new(
            SignatureFormat::ASiC,
            "ASiC-XAdES",
            "XAdES XML signatures inside ASiC containers are recognised but not generated or validated by this crate",
        )
        .with_evidence(evidence)
        .with_supported_profiles(["ASiC-S/CAdES single payload", "ASiC-E/CAdES single manifest"]),
    )
}

fn read_zip_member_for_inspection<R: Read>(
    name: &str,
    file: &mut R,
    declared_size: u64,
) -> Result<Vec<u8>, SigningError> {
    let capacity = declared_size.min(ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES + 1) as usize;
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = file.take(ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|e| asic_err(format!("failed to read ASiC ZIP member {name}: {e}")))?;
    Ok(bytes)
}

fn account_zip_member_for_inspection<R: Read>(
    name: &str,
    file: &mut R,
    size_budget: &mut ZipSizeBudget,
    global_blockers: &mut Vec<AsicDiagnosticBlocker>,
) -> Result<(u64, ZipMemberSizeInspection), SigningError> {
    let mut limited = file.take(ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES + 1);
    let actual_size = std::io::copy(&mut limited, &mut std::io::sink())
        .map_err(|e| asic_err(format!("failed to read ASiC ZIP member {name}: {e}")))?;
    let inspection = size_budget.inspect_actual_consumed(name, actual_size, global_blockers);
    Ok((actual_size, inspection))
}

fn read_zip_member<R: Read>(
    name: &str,
    file: &mut R,
    declared_size: u64,
) -> Result<Vec<u8>, SigningError> {
    check_zip_member_uncompressed_size(name, declared_size, ZipSizeObservation::Declared)?;
    let capacity = usize::try_from(declared_size).map_err(|_| {
        zip_member_uncompressed_size_error(name, declared_size, ZipSizeObservation::Declared)
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = file.take(ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|e| asic_err(format!("failed to read ASiC ZIP member {name}: {e}")))?;
    if bytes.len() as u64 > ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES {
        return Err(zip_member_uncompressed_size_error(
            name,
            bytes.len() as u64,
            ZipSizeObservation::Actual,
        ));
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy)]
enum ZipSizeObservation {
    Declared,
    Actual,
}

fn check_zip_member_uncompressed_size(
    name: &str,
    size: u64,
    observation: ZipSizeObservation,
) -> Result<(), SigningError> {
    if size > ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES {
        return Err(zip_member_uncompressed_size_error(name, size, observation));
    }
    Ok(())
}

fn zip_member_uncompressed_size_error(
    name: &str,
    size: u64,
    observation: ZipSizeObservation,
) -> SigningError {
    asic_err(zip_member_uncompressed_size_message(
        name,
        size,
        observation,
    ))
}

fn zip_member_uncompressed_size_message(
    name: &str,
    size: u64,
    observation: ZipSizeObservation,
) -> String {
    match observation {
        ZipSizeObservation::Declared => format!(
            "ASiC ZIP member {name} declares {size} uncompressed bytes; maximum supported member size is {ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES} bytes"
        ),
        ZipSizeObservation::Actual => format!(
            "ASiC ZIP member {name} decompressed to {size} bytes; maximum supported member size is {ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES} bytes"
        ),
    }
}

fn zip_total_uncompressed_size_error(
    name: &str,
    total: u64,
    observation: ZipSizeObservation,
) -> SigningError {
    asic_err(zip_total_uncompressed_size_message(
        name,
        total,
        observation,
    ))
}

fn zip_total_uncompressed_size_message(
    name: &str,
    total: u64,
    observation: ZipSizeObservation,
) -> String {
    match observation {
        ZipSizeObservation::Declared => format!(
            "ASiC ZIP members declare at least {total} uncompressed bytes through {name}; maximum supported total uncompressed size is {ASIC_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES} bytes"
        ),
        ZipSizeObservation::Actual => format!(
            "ASiC ZIP members decompressed to {total} bytes through {name}; maximum supported total uncompressed size is {ASIC_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES} bytes"
        ),
    }
}

fn validate_payload_name(name: &str) -> Result<(), SigningError> {
    validate_member_name(name)?;
    if name.ends_with('/') {
        return Err(asic_err("ASiC payload member name must be a file"));
    }
    if name.eq_ignore_ascii_case(MIMETYPE_PATH) || is_meta_inf_path(name) {
        return Err(asic_err(
            "ASiC payload member name must not be mimetype or inside META-INF",
        ));
    }
    Ok(())
}

fn validate_payloads(payloads: &[AsicPayload<'_>]) -> Result<(), SigningError> {
    if payloads.is_empty() {
        return Err(asic_err("ASiC-E requires at least one payload"));
    }

    let mut seen = HashSet::new();
    for payload in payloads {
        validate_payload_name(payload.name)?;
        if !seen.insert(payload.name.to_ascii_lowercase()) {
            return Err(asic_err(format!(
                "duplicate ASiC-E payload member {}",
                payload.name
            )));
        }
        if let Some(mime_type) = payload.mime_type {
            validate_mime_type(mime_type)?;
        }
    }

    Ok(())
}

fn validate_mime_type(mime_type: &str) -> Result<(), SigningError> {
    if mime_type.is_empty()
        || mime_type
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(asic_err(format!(
            "invalid ASiC manifest media type {mime_type}"
        )));
    }
    Ok(())
}

fn validate_cades_signature_path(name: &str) -> Result<(), SigningError> {
    validate_member_name(name)?;
    if !is_cades_signature_path(name) {
        return Err(asic_err(format!(
            "ASiC-E CAdES signature reference {name} must be a META-INF/*signature*.p7s member"
        )));
    }
    Ok(())
}

pub(crate) fn validate_member_name(name: &str) -> Result<(), SigningError> {
    if name.is_empty() {
        return Err(asic_err("ASiC ZIP member name must not be empty"));
    }
    if name.contains('\\') || name.starts_with('/') || name.contains('\0') {
        return Err(asic_err(format!("unsafe ASiC ZIP member name {name}")));
    }

    let path = name.strip_suffix('/').unwrap_or(name);
    if path.is_empty() {
        return Err(asic_err(format!("unsafe ASiC ZIP member name {name}")));
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(asic_err(format!("unsafe ASiC ZIP member name {name}")));
    }

    Ok(())
}

pub(crate) fn is_xades_signature_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "meta-inf/signature.xml"
        || lower == "meta-inf/signatures.xml"
        || (lower.starts_with("meta-inf/signature") && lower.ends_with(".xml"))
}

pub(crate) fn is_asic_manifest_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("meta-inf/asicmanifest") && lower.ends_with(".xml")
}

/// Whether `name` is an ASiCArchiveManifest member (`META-INF/ASiCArchiveManifest*.xml`).
pub(crate) fn is_archive_manifest_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("meta-inf/asicarchivemanifest") && lower.ends_with(".xml")
}

/// Whether `name` is an RFC 3161 archive-timestamp token member (`META-INF/*.tst`).
pub(crate) fn is_timestamp_token_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_meta_inf_path(name) && lower.ends_with(".tst")
}

pub(crate) fn is_cades_signature_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("meta-inf/")
        && lower.ends_with(".p7s")
        && lower
            .rsplit_once('/')
            .map(|(_, file_name)| file_name.contains("signature"))
            .unwrap_or(false)
}

pub(crate) fn is_meta_inf_path(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("meta-inf/")
}

#[derive(Debug)]
struct ParsedAsicEManifest {
    signature_path: String,
    data_objects: Vec<ParsedDataObjectReference>,
}

#[derive(Debug)]
struct ParsedDataObjectReference {
    name: String,
    mime_type: Option<String>,
    sha256_digest: [u8; 32],
}

fn parse_asic_e_manifest(manifest: &[u8]) -> Result<ParsedAsicEManifest, SigningError> {
    let xml = std::str::from_utf8(manifest)
        .map_err(|_| asic_err("ASiC-E ASiCManifest is not valid UTF-8 XML"))?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut depth = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut sig_reference: Option<String> = None;
    let mut data_objects = Vec::new();
    let mut current_data_object: Option<ManifestDataObjectBuilder> = None;
    let mut current_text = String::new();
    let mut in_digest_value = false;
    let mut in_sig_reference = false;
    let mut in_digest_method = false;
    let mut saw_data_object = false;

    loop {
        match reader
            .read_event()
            .map_err(|e| asic_err(format!("ASiC-E ASiCManifest XML is malformed: {e}")))?
        {
            Event::Start(e) => {
                let next_depth = depth + 1;
                handle_manifest_start(
                    &e,
                    next_depth,
                    &mut root_seen,
                    &mut sig_reference,
                    &mut current_data_object,
                    &mut in_sig_reference,
                    &mut in_digest_method,
                    &mut in_digest_value,
                    &mut current_text,
                    &mut saw_data_object,
                )?;
                depth = next_depth;
            }
            Event::Empty(e) => {
                let next_depth = depth + 1;
                handle_manifest_empty(
                    &e,
                    next_depth,
                    &mut root_seen,
                    &mut sig_reference,
                    &mut current_data_object,
                    &mut saw_data_object,
                )?;
            }
            Event::Text(e) => {
                let text = e
                    .xml_content(quick_xml::XmlVersion::Implicit1_0)
                    .map_err(|e| asic_err(format!("ASiC-E ASiCManifest text is invalid: {e}")))?;
                if in_digest_value {
                    current_text.push_str(&text);
                } else if !text.trim().is_empty() {
                    return Err(asic_err(
                        "ASiC-E ASiCManifest contains unsupported text content",
                    ));
                }
            }
            Event::CData(_) => {
                return Err(asic_err(
                    "ASiC-E ASiCManifest CDATA content is not supported",
                ));
            }
            Event::End(e) => {
                if depth == 0 {
                    return Err(asic_err(
                        "ASiC-E ASiCManifest has an unexpected closing tag",
                    ));
                }
                let local = local_name(e.name().as_ref());
                match depth {
                    1 if local == "ASiCManifest" => {
                        root_closed = true;
                    }
                    2 if local == "SigReference" => {
                        in_sig_reference = false;
                    }
                    2 if local == "DataObjectReference" => {
                        let data_object = current_data_object.take().ok_or_else(|| {
                            asic_err("ASiC-E DataObjectReference parser state is invalid")
                        })?;
                        data_objects.push(data_object.finish()?);
                    }
                    3 if local == "DigestMethod" => {
                        in_digest_method = false;
                    }
                    3 if local == "DigestValue" => {
                        in_digest_value = false;
                        let digest = parse_digest_text(&current_text)?;
                        current_text.clear();
                        let data_object = current_data_object.as_mut().ok_or_else(|| {
                            asic_err("ASiC-E DigestValue appeared outside DataObjectReference")
                        })?;
                        if data_object.sha256_digest.replace(digest).is_some() {
                            return Err(asic_err(
                                "ASiC-E DataObjectReference contains multiple DigestValue elements",
                            ));
                        }
                    }
                    _ => {
                        return Err(asic_err(format!(
                            "unsupported ASiC-E ASiCManifest closing element {local}"
                        )));
                    }
                }
                depth -= 1;
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if !root_seen || !root_closed || depth != 0 {
        return Err(asic_err("ASiC-E ASiCManifest is incomplete"));
    }
    let signature_path =
        sig_reference.ok_or_else(|| asic_err("ASiC-E ASiCManifest is missing SigReference"))?;
    if data_objects.is_empty() {
        return Err(asic_err(
            "ASiC-E ASiCManifest is missing DataObjectReference entries",
        ));
    }

    Ok(ParsedAsicEManifest {
        signature_path,
        data_objects,
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_manifest_start(
    e: &BytesStart<'_>,
    depth: usize,
    root_seen: &mut bool,
    sig_reference: &mut Option<String>,
    current_data_object: &mut Option<ManifestDataObjectBuilder>,
    in_sig_reference: &mut bool,
    in_digest_method: &mut bool,
    in_digest_value: &mut bool,
    current_text: &mut String,
    saw_data_object: &mut bool,
) -> Result<(), SigningError> {
    let local = local_name(e.name().as_ref());
    match depth {
        1 if local == "ASiCManifest" => {
            if *root_seen {
                return Err(asic_err("ASiC-E ASiCManifest contains multiple roots"));
            }
            validate_manifest_root_namespace(e)?;
            *root_seen = true;
        }
        2 if local == "SigReference" => {
            if sig_reference.is_some() {
                return Err(asic_err(
                    "ASiC-E ASiCManifest contains multiple SigReference elements",
                ));
            }
            if *saw_data_object {
                return Err(asic_err(
                    "ASiC-E ASiCManifest SigReference must precede DataObjectReference elements",
                ));
            }
            *sig_reference = Some(parse_sig_reference(e)?);
            *in_sig_reference = true;
        }
        2 if local == "DataObjectReference" => {
            if sig_reference.is_none() {
                return Err(asic_err(
                    "ASiC-E ASiCManifest DataObjectReference appeared before SigReference",
                ));
            }
            *saw_data_object = true;
            *current_data_object = Some(parse_data_object_reference_start(e)?);
        }
        2 if local == "ASiCManifestExtensions" => {
            return Err(asic_err(
                "ASiC-E ASiCManifestExtensions are not supported in this bounded implementation",
            ));
        }
        3 if current_data_object.is_some() && local == "DigestMethod" => {
            parse_digest_method(e, current_data_object)?;
            *in_digest_method = true;
        }
        3 if current_data_object.is_some() && local == "DigestValue" => {
            *in_digest_value = true;
            current_text.clear();
        }
        3 if current_data_object.is_some() && local == "DataObjectReferenceExtensions" => {
            return Err(asic_err(
                "ASiC-E DataObjectReferenceExtensions are not supported in this bounded implementation",
            ));
        }
        _ if *in_sig_reference => {
            return Err(asic_err(
                "ASiC-E SigReference contains unsupported nested elements",
            ));
        }
        _ if *in_digest_method => {
            return Err(asic_err(
                "ASiC-E DigestMethod contains unsupported nested elements",
            ));
        }
        _ if *in_digest_value => {
            return Err(asic_err(
                "ASiC-E DigestValue contains unsupported nested elements",
            ));
        }
        _ => {
            return Err(asic_err(format!(
                "unsupported ASiC-E ASiCManifest element {local}"
            )));
        }
    }
    Ok(())
}

fn handle_manifest_empty(
    e: &BytesStart<'_>,
    depth: usize,
    root_seen: &mut bool,
    sig_reference: &mut Option<String>,
    current_data_object: &mut Option<ManifestDataObjectBuilder>,
    saw_data_object: &mut bool,
) -> Result<(), SigningError> {
    let local = local_name(e.name().as_ref());
    match depth {
        1 if local == "ASiCManifest" => Err(asic_err(
            "ASiC-E ASiCManifest is missing required child elements",
        )),
        2 if local == "SigReference" => {
            if !*root_seen {
                return Err(asic_err("ASiC-E SigReference appeared before ASiCManifest"));
            }
            if sig_reference.is_some() {
                return Err(asic_err(
                    "ASiC-E ASiCManifest contains multiple SigReference elements",
                ));
            }
            if *saw_data_object {
                return Err(asic_err(
                    "ASiC-E ASiCManifest SigReference must precede DataObjectReference elements",
                ));
            }
            *sig_reference = Some(parse_sig_reference(e)?);
            Ok(())
        }
        2 if local == "DataObjectReference" => Err(asic_err(
            "ASiC-E DataObjectReference is missing DigestMethod and DigestValue",
        )),
        2 if local == "ASiCManifestExtensions" => Err(asic_err(
            "ASiC-E ASiCManifestExtensions are not supported in this bounded implementation",
        )),
        3 if current_data_object.is_some() && local == "DigestMethod" => {
            parse_digest_method(e, current_data_object)
        }
        3 if current_data_object.is_some() && local == "DigestValue" => {
            Err(asic_err("ASiC-E DigestValue is empty"))
        }
        3 if current_data_object.is_some() && local == "DataObjectReferenceExtensions" => {
            Err(asic_err(
                "ASiC-E DataObjectReferenceExtensions are not supported in this bounded implementation",
            ))
        }
        _ => Err(asic_err(format!(
            "unsupported ASiC-E ASiCManifest element {local}"
        ))),
    }
}

#[derive(Debug)]
struct ManifestDataObjectBuilder {
    name: String,
    mime_type: Option<String>,
    digest_method_seen: bool,
    sha256_digest: Option<[u8; 32]>,
}

impl ManifestDataObjectBuilder {
    fn finish(self) -> Result<ParsedDataObjectReference, SigningError> {
        if !self.digest_method_seen {
            return Err(asic_err(
                "ASiC-E DataObjectReference is missing DigestMethod",
            ));
        }
        let sha256_digest = self
            .sha256_digest
            .ok_or_else(|| asic_err("ASiC-E DataObjectReference is missing DigestValue"))?;
        Ok(ParsedDataObjectReference {
            name: self.name,
            mime_type: self.mime_type,
            sha256_digest,
        })
    }
}

fn parse_sig_reference(e: &BytesStart<'_>) -> Result<String, SigningError> {
    let uri = required_attr(e, "URI", "SigReference")?;
    validate_cades_signature_path(&uri)?;
    if let Some(mime_type) = attr_value(e, "MimeType")? {
        validate_mime_type(&mime_type)?;
        if mime_type != CADES_SIGNATURE_MIME_TYPE {
            return Err(asic_err(format!(
                "ASiC-E SigReference MimeType {mime_type} is not supported"
            )));
        }
    }
    Ok(uri)
}

fn parse_data_object_reference_start(
    e: &BytesStart<'_>,
) -> Result<ManifestDataObjectBuilder, SigningError> {
    let uri = required_attr(e, "URI", "DataObjectReference")?;
    validate_payload_name(&uri)?;
    let mime_type = attr_value(e, "MimeType")?;
    if let Some(mime_type) = mime_type.as_deref() {
        validate_mime_type(mime_type)?;
    }
    Ok(ManifestDataObjectBuilder {
        name: uri,
        mime_type,
        digest_method_seen: false,
        sha256_digest: None,
    })
}

fn parse_digest_method(
    e: &BytesStart<'_>,
    current_data_object: &mut Option<ManifestDataObjectBuilder>,
) -> Result<(), SigningError> {
    let data_object = current_data_object
        .as_mut()
        .ok_or_else(|| asic_err("ASiC-E DigestMethod appeared outside DataObjectReference"))?;
    if data_object.digest_method_seen {
        return Err(asic_err(
            "ASiC-E DataObjectReference contains multiple DigestMethod elements",
        ));
    }
    let algorithm = required_attr(e, "Algorithm", "DigestMethod")?;
    if algorithm != SHA256_DIGEST_METHOD_URI {
        return Err(asic_err(format!(
            "ASiC-E DataObjectReference digest method {algorithm} is not supported"
        )));
    }
    data_object.digest_method_seen = true;
    Ok(())
}

fn parse_digest_text(text: &str) -> Result<[u8; 32], SigningError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(asic_err("ASiC-E DigestValue is empty"));
    }
    let bytes = BASE64_STANDARD
        .decode(text)
        .map_err(|_| asic_err("ASiC-E DigestValue is not valid base64"))?;
    bytes
        .try_into()
        .map_err(|_| asic_err("ASiC-E DigestValue is not a SHA-256 digest"))
}

fn validate_manifest_root_namespace(e: &BytesStart<'_>) -> Result<(), SigningError> {
    let mut asic_ns_ok = false;
    let mut ds_ns_ok = false;
    for attr in e.attributes() {
        let attr = attr.map_err(|e| asic_err(format!("ASiC-E XML attribute is invalid: {e}")))?;
        let key = String::from_utf8_lossy(attr.key.as_ref());
        let value = String::from_utf8_lossy(&attr.value);
        if (key == "xmlns:asic" || key == "xmlns") && value == ASIC_NS {
            asic_ns_ok = true;
        }
        if key == "xmlns:ds" && value == DS_NS {
            ds_ns_ok = true;
        }
    }
    if !asic_ns_ok || !ds_ns_ok {
        return Err(asic_err(
            "ASiC-E ASiCManifest must declare the ASiC and XMLDSig namespaces",
        ));
    }
    Ok(())
}

fn required_attr(e: &BytesStart<'_>, attr: &str, element: &str) -> Result<String, SigningError> {
    attr_value(e, attr)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            asic_err(format!(
                "ASiC-E {element} is missing required {attr} attribute"
            ))
        })
}

fn attr_value(e: &BytesStart<'_>, attr_name: &str) -> Result<Option<String>, SigningError> {
    for attr in e.attributes() {
        let attr = attr.map_err(|e| asic_err(format!("ASiC-E XML attribute is invalid: {e}")))?;
        if local_name(attr.key.as_ref()) == attr_name {
            return Ok(Some(String::from_utf8_lossy(&attr.value).into_owned()));
        }
    }
    Ok(None)
}

fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_owned(),
        None => s.into_owned(),
    }
}

fn escape_xml_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn zip_err(context: &str, error: zip::result::ZipError) -> SigningError {
    asic_err(format!("{context}: {error}"))
}

fn asic_err(message: impl Into<String>) -> SigningError {
    SigningError::Asic(message.into())
}
