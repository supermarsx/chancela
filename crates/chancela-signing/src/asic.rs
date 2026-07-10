//! Bounded ASiC evidence-container support.
//!
//! This module implements the narrow ASiC shape this crate can truthfully support today:
//! a single payload in an ASiC-S ZIP container plus one detached CAdES-B signature, or an
//! ASiC-E/CAdES ZIP container where one ASiC manifest references multiple payload digests and one
//! CAdES signature over that manifest. It does not implement XAdES signatures, timestamp
//! manifests, archival timestamps, multiple ASiC-E signatures, or any legal qualification decision.

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Write};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
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
/// The ASiC-E manifest member this implementation creates and validates.
pub const ASICE_MANIFEST_PATH: &str = "META-INF/ASiCManifest.xml";
/// The ASiC-E detached CAdES signature member this implementation creates and validates.
pub const ASICE_CADES_SIGNATURE_PATH: &str = "META-INF/signature001.p7s";

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

/// Parse and validate either bounded ASiC shape implemented by this crate.
pub fn extract_asic_container(container: &[u8]) -> Result<AsicContainer, SigningError> {
    match detect_mimetype(container)? {
        AsicMimeKind::S => extract_asic_s_container(container).map(AsicContainer::S),
        AsicMimeKind::E => extract_asic_e_container(container).map(AsicContainer::E),
    }
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
            let bytes = read_zip_member(&name, &mut file)?;
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
            let bytes = read_zip_member(&name, &mut file)?;
            if bytes.is_empty() {
                return Err(asic_err(format!(
                    "ASiC-E CAdES signature member {name} is empty"
                )));
            }
            meta_inf_files.insert(name, bytes);
            continue;
        }

        validate_payload_name(&name)?;
        payloads.insert(name.clone(), read_zip_member(&name, &mut file)?);
    }

    if !xades_signature_paths.is_empty() {
        return Err(asic_err(format!(
            "ASiC-E containers with XAdES XML signatures are not supported; found {}",
            xades_signature_paths.join(", ")
        )));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsicMimeKind {
    S,
    E,
}

fn detect_mimetype(container: &[u8]) -> Result<AsicMimeKind, SigningError> {
    let mut archive = ZipArchive::new(Cursor::new(container))
        .map_err(|e| zip_err("ASiC container is not a readable ZIP archive", e))?;
    if archive.is_empty() {
        return Err(asic_err("ASiC container ZIP archive is empty"));
    }
    read_mimetype(&mut archive)
}

fn read_and_check_mimetype(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Result<(), SigningError> {
    match read_mimetype(archive)? {
        AsicMimeKind::S => Ok(()),
        AsicMimeKind::E => Err(asic_err(
            "ASiC-E containers must be parsed through the ASiC-E/CAdES manifest path",
        )),
    }
}

fn read_and_check_asice_mimetype(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
) -> Result<(), SigningError> {
    match read_mimetype(archive)? {
        AsicMimeKind::E => Ok(()),
        AsicMimeKind::S => Err(asic_err(
            "ASiC-S containers must be parsed through the ASiC-S/CAdES path",
        )),
    }
}

fn read_mimetype(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Result<AsicMimeKind, SigningError> {
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
    let mut mimetype = String::new();
    first
        .read_to_string(&mut mimetype)
        .map_err(|e| asic_err(format!("failed to read ASiC mimetype member: {e}")))?;

    match mimetype.as_str() {
        ASICS_MIMETYPE => Ok(AsicMimeKind::S),
        ASICE_MIMETYPE => Ok(AsicMimeKind::E),
        other => Err(asic_err(format!(
            "unsupported ASiC mimetype {other}; expected {ASICS_MIMETYPE} or {ASICE_MIMETYPE}"
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

fn is_asic_manifest_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("meta-inf/asicmanifest") && lower.ends_with(".xml")
}

fn is_cades_signature_path(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("meta-inf/")
        && lower.ends_with(".p7s")
        && lower
            .rsplit_once('/')
            .map(|(_, file_name)| file_name.contains("signature"))
            .unwrap_or(false)
}

fn is_meta_inf_path(name: &str) -> bool {
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
