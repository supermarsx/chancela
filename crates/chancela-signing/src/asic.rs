//! Bounded ASiC-S evidence-container support.
//!
//! This module implements the narrow ASiC shape this crate can truthfully support today:
//! a single payload in an ASiC-S ZIP container plus one detached CAdES-B signature at
//! `META-INF/signatures.p7s`. It does not implement ASiC-E, XAdES signatures, timestamp
//! manifests, archival timestamps, or any legal qualification decision.

use std::collections::HashSet;
use std::io::{Cursor, Read, Write};

use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use crate::SigningError;

/// The ASiC-S MIME type stored in the first, uncompressed ZIP member.
pub const ASICS_MIMETYPE: &str = "application/vnd.etsi.asic-s+zip";
/// ASiC-E is recognised explicitly but remains outside this bounded implementation.
pub const ASICE_MIMETYPE: &str = "application/vnd.etsi.asic-e+zip";
/// The detached CAdES signature member this implementation creates and validates.
pub const ASICS_CADES_SIGNATURE_PATH: &str = "META-INF/signatures.p7s";

const MIMETYPE_PATH: &str = "mimetype";
const META_INF_PREFIX: &str = "META-INF/";

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
        if file.is_dir() {
            continue;
        }

        if name == MIMETYPE_PATH {
            continue;
        }
        if name == ASICS_CADES_SIGNATURE_PATH {
            let bytes = read_zip_member(&name, &mut file)?;
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
        let bytes = read_zip_member(&name, &mut file)?;
        content = Some((name, bytes));
    }

    if !xades_signature_paths.is_empty() {
        return Err(asic_err(format!(
            "ASiC containers with XAdES XML signatures are not supported; found {}",
            xades_signature_paths.join(", ")
        )));
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

fn read_and_check_mimetype(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Result<(), SigningError> {
    let mut first = archive
        .by_index(0)
        .map_err(|e| zip_err("failed to read first ASiC ZIP member", e))?;
    let name = first.name().to_owned();
    validate_member_name(&name)?;
    if name != MIMETYPE_PATH {
        return Err(asic_err(format!(
            "ASiC-S requires the first ZIP member to be mimetype, got {name}"
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
    let mut mimetype = String::new();
    first
        .read_to_string(&mut mimetype)
        .map_err(|e| asic_err(format!("failed to read ASiC mimetype member: {e}")))?;

    match mimetype.as_str() {
        ASICS_MIMETYPE => Ok(()),
        ASICE_MIMETYPE => Err(asic_err(
            "ASiC-E containers are not supported; only single-payload ASiC-S/CAdES is implemented",
        )),
        other => Err(asic_err(format!(
            "unsupported ASiC mimetype {other}; expected {ASICS_MIMETYPE}"
        ))),
    }
}

fn read_zip_member<R: Read>(name: &str, file: &mut R) -> Result<Vec<u8>, SigningError> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| asic_err(format!("failed to read ASiC ZIP member {name}: {e}")))?;
    Ok(bytes)
}

fn validate_payload_name(name: &str) -> Result<(), SigningError> {
    validate_member_name(name)?;
    if name.ends_with('/') {
        return Err(asic_err("ASiC-S payload member name must be a file"));
    }
    if name.eq_ignore_ascii_case(MIMETYPE_PATH) || is_meta_inf_path(name) {
        return Err(asic_err(
            "ASiC-S payload member name must not be mimetype or inside META-INF",
        ));
    }
    Ok(())
}

fn validate_member_name(name: &str) -> Result<(), SigningError> {
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

fn is_xades_signature_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "meta-inf/signature.xml"
        || lower == "meta-inf/signatures.xml"
        || (lower.starts_with("meta-inf/signatures") && lower.ends_with(".xml"))
}

fn is_meta_inf_path(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("meta-inf/")
}

fn zip_err(context: &str, error: zip::result::ZipError) -> SigningError {
    asic_err(format!("{context}: {error}"))
}

fn asic_err(message: impl Into<String>) -> SigningError {
    SigningError::Asic(message.into())
}
