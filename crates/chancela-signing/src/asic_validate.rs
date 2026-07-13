//! The local ASiC validation surface: open a container, classify it, enumerate every recognised
//! signature, and verify each one cryptographically against the content it binds.
//!
//! This is the read side of [`crate::asic_sign`]. It handles both the bounded single-signature
//! shapes and the multi-signature containers produced by this crate:
//!
//! - **CAdES** (`chancela-cades`): an ASiC-S/CAdES signature covers the single payload digest; an
//!   ASiC-E/CAdES signature covers its own `ASiCManifest`, whose `DataObjectReference` digests are
//!   re-checked against the packaged payloads.
//! - **XAdES** (`chancela_xades::validate_xades`): the signature is verified over its canonical
//!   `SignedInfo`; each detached `ds:Reference` digest is then re-derived from the packaged payload
//!   it names (the ASiC binding a bare-XML validator cannot perform without the container).
//! - **ASiCArchiveManifest**: the RFC 3161 archive-timestamp imprint is checked against the archive
//!   manifest bytes, and every `DataObjectReference` digest against the member it covers.
//!
//! Like the CAdES/XAdES validators it wraps, a valid report means "cryptographically valid over the
//! bound content", never "the signer is trusted" — trust-chain and qualified-status resolution stay
//! a `chancela-tsl` job.

use std::io::{Cursor, Read};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use time::OffsetDateTime;
use zip::ZipArchive;

use chancela_xades::{XadesLevel, validate_xades};

use crate::SigningError;
use crate::asic::{
    ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES, ASIC_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES, ASICE_MIMETYPE,
    ASICS_MIMETYPE, AsicContainerKind, AsicSignatureMemberKind, AsicSignatureProfile,
    is_archive_manifest_path, is_asic_manifest_path, is_cades_signature_path, is_meta_inf_path,
    is_timestamp_token_path, is_xades_signature_path, sha256_content_digest, validate_member_name,
};

/// Loaded ASiC ZIP members, as `(member name, bytes)` excluding `mimetype`.
type AsicMembers = Vec<(String, Vec<u8>)>;

const ASIC_NS: &str = "http://uri.etsi.org/02918/v1.2.1#";
const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const MIMETYPE_PATH: &str = "mimetype";

/// `id-signedData` and `id-ct-TSTInfo` OIDs for the archive-timestamp token.
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// The validation outcome for one ASiC signature member.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AsicSignatureValidation {
    /// The signature member path.
    pub path: String,
    /// CAdES or XAdES.
    pub kind: AsicSignatureMemberKind,
    /// For an ASiC-E/CAdES signature, the `ASiCManifest` member it covers.
    pub manifest_path: Option<String>,
    /// Whether the signature is cryptographically valid over the content it binds, and every bound
    /// digest matched the packaged bytes.
    pub valid: bool,
    /// The signer certificate DER recovered from the signature, if any.
    pub signer_cert_der: Option<Vec<u8>>,
    /// The signing time asserted by the signature, if present.
    pub signing_time: Option<OffsetDateTime>,
    /// The container member paths this signature binds (payloads it covers).
    pub covered_data_objects: Vec<String>,
    /// For a XAdES signature, the detected conformance level.
    pub xades_level: Option<XadesLevel>,
    /// Whether a signature timestamp (B-T / XAdES-T) is present.
    pub has_signature_timestamp: bool,
    /// Structured reasons the signature was rejected (empty when `valid`).
    pub failure_reasons: Vec<String>,
}

/// The validation outcome for one `ASiCArchiveManifest` + its archive timestamp.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AsicArchiveTimestampValidation {
    /// The archive manifest member path.
    pub manifest_path: String,
    /// The RFC 3161 archive-timestamp token member the manifest references.
    pub timestamp_path: String,
    /// Whether the token's SHA-256 imprint attests the archive manifest bytes.
    pub imprint_matches_manifest: bool,
    /// Whether every `DataObjectReference` digest matched its covered member.
    pub references_valid: bool,
    /// The container members the archive manifest covers (that were present and matched).
    pub covered_members: Vec<String>,
    /// The archive timestamp's `genTime`, if the token parsed.
    pub gen_time: Option<OffsetDateTime>,
    /// Whether the archive-timestamp evidence is internally consistent.
    pub valid: bool,
    /// Structured reasons the archive timestamp was rejected (empty when `valid`).
    pub failure_reasons: Vec<String>,
}

/// A local, caller-supplied embedded evidence indicator found inside ASiC members.
///
/// These indicators report member/element presence only. They do not perform trust anchoring,
/// revocation fetching, or legal long-term-profile sufficiency checks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicEmbeddedEvidenceIndicator {
    /// Stable snake-case diagnostic code.
    pub code: String,
    /// The ASiC member where the indicator was found.
    pub source_path: String,
    /// Technical category: `signature_timestamp`, `lt_evidence`, or `lta_evidence`.
    pub evidence_kind: String,
    /// Human-readable local diagnostic detail.
    pub message: String,
}

/// A local blocker that prevents interpreting embedded ASiC evidence as a complete LT/LTA shape.
///
/// These blockers are not trust/legal findings; they only describe missing, malformed, or
/// unreferenced local members/elements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AsicEmbeddedEvidenceBlocker {
    /// Stable snake-case diagnostic code.
    pub code: String,
    /// The ASiC member most directly associated with the blocker.
    pub source_path: String,
    /// Human-readable local diagnostic detail.
    pub message: String,
}

/// A technical/local ASiC container validation report.
///
/// This is a technical cryptographic report only; it makes no legal qualification or
/// probative-value claim.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AsicValidationReport {
    /// The container family from the ZIP `mimetype`.
    pub container_kind: AsicContainerKind,
    /// The signature technology found across members.
    pub signature_profile: AsicSignatureProfile,
    /// Per-signature validation, in member order.
    pub signatures: Vec<AsicSignatureValidation>,
    /// Per-archive-manifest validation, in member order.
    pub archive_timestamps: Vec<AsicArchiveTimestampValidation>,
    /// Local indicators for embedded signature timestamp, LT-like, or LTA-like evidence.
    pub embedded_evidence_indicators: Vec<AsicEmbeddedEvidenceIndicator>,
    /// Local blockers for interpreting embedded evidence as a complete LT/LTA technical shape.
    pub embedded_evidence_blockers: Vec<AsicEmbeddedEvidenceBlocker>,
    /// Container-level failures (structure the walk could not attribute to one signature).
    pub failure_reasons: Vec<String>,
}

impl AsicValidationReport {
    /// Whether at least one signature was found and every signature validated.
    pub fn all_signatures_valid(&self) -> bool {
        !self.signatures.is_empty() && self.signatures.iter().all(|s| s.valid)
    }

    /// Whether every signature and every archive timestamp validated and there are no container
    /// failures. This is a technical validity result, not a legal-sufficiency claim.
    pub fn is_valid(&self) -> bool {
        self.failure_reasons.is_empty()
            && self.all_signatures_valid()
            && self.archive_timestamps.iter().all(|a| a.valid)
    }
}

/// Open and cryptographically validate an ASiC container across all supported shapes.
pub fn validate_asic_container(container: &[u8]) -> Result<AsicValidationReport, SigningError> {
    let (container_kind, members) = load_members(container)?;

    let mut payloads: Vec<(&str, &[u8])> = Vec::new();
    let mut cades_paths: Vec<&str> = Vec::new();
    let mut xades_paths: Vec<&str> = Vec::new();
    let mut manifest_paths: Vec<&str> = Vec::new();
    let mut archive_manifest_paths: Vec<&str> = Vec::new();
    for (name, bytes) in &members {
        if is_archive_manifest_path(name) {
            archive_manifest_paths.push(name);
        } else if is_asic_manifest_path(name) {
            manifest_paths.push(name);
        } else if is_cades_signature_path(name) {
            cades_paths.push(name);
        } else if is_xades_signature_path(name) {
            xades_paths.push(name);
        } else if is_timestamp_token_path(name) || is_meta_inf_path(name) {
            // Archive-timestamp tokens and any other META-INF members are handled by reference.
        } else {
            payloads.push((name, bytes));
        }
    }

    let signature_profile = match (cades_paths.is_empty(), xades_paths.is_empty()) {
        (false, false) => AsicSignatureProfile::Mixed,
        (false, true) => AsicSignatureProfile::Cades,
        (true, false) => AsicSignatureProfile::Xades,
        (true, true) => AsicSignatureProfile::Unsigned,
    };

    let mut signatures = Vec::new();
    let mut failure_reasons = Vec::new();

    for path in &cades_paths {
        let cades = member(&members, path).expect("member enumerated from the same map");
        signatures.push(validate_cades_signature(
            container_kind,
            path,
            cades,
            &payloads,
            &manifest_paths,
            &members,
        ));
    }
    for path in &xades_paths {
        let xml = member(&members, path).expect("member enumerated from the same map");
        signatures.push(validate_xades_signature(path, xml, &payloads));
    }

    let mut archive_timestamps = Vec::new();
    for path in &archive_manifest_paths {
        let manifest = member(&members, path).expect("member enumerated from the same map");
        archive_timestamps.push(validate_archive_manifest(path, manifest, &members));
    }
    let (embedded_evidence_indicators, embedded_evidence_blockers) =
        diagnose_embedded_evidence(&members, &xades_paths, &archive_timestamps);

    if signatures.is_empty() {
        failure_reasons.push("ASiC container carries no recognised signature member".to_string());
    }

    Ok(AsicValidationReport {
        container_kind,
        signature_profile,
        signatures,
        archive_timestamps,
        embedded_evidence_indicators,
        embedded_evidence_blockers,
        failure_reasons,
    })
}

/// Look up a container member's bytes by exact name.
fn member<'a>(members: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    members
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, b)| b.as_slice())
}

/// Read every ZIP member into memory under the crate's per-member and total uncompressed-size caps,
/// returning the declared container family and the member bytes (excluding `mimetype`).
fn load_members(container: &[u8]) -> Result<(AsicContainerKind, AsicMembers), SigningError> {
    let mut archive = ZipArchive::new(Cursor::new(container))
        .map_err(|e| SigningError::Asic(format!("ASiC container is not a readable ZIP: {e}")))?;
    if archive.is_empty() {
        return Err(SigningError::Asic(
            "ASiC container ZIP is empty".to_string(),
        ));
    }

    let mut kind: Option<AsicContainerKind> = None;
    let mut members = Vec::new();
    let mut total: u64 = 0;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|e| SigningError::Asic(format!("failed to read ASiC ZIP member: {e}")))?;
        let name = file.name().to_owned();
        validate_member_name(&name)?;
        if file.encrypted() {
            return Err(SigningError::Asic(format!(
                "encrypted ASiC ZIP member {name} is not supported"
            )));
        }
        if file.is_dir() {
            continue;
        }
        if file.size() > ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES {
            return Err(SigningError::Asic(format!(
                "ASiC ZIP member {name} exceeds the maximum supported member size"
            )));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                SigningError::Asic(format!("failed to read ASiC ZIP member {name}: {e}"))
            })?;
        if bytes.len() as u64 > ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES {
            return Err(SigningError::Asic(format!(
                "ASiC ZIP member {name} decompressed past the maximum supported member size"
            )));
        }
        total = total.saturating_add(bytes.len() as u64);
        if total > ASIC_ZIP_TOTAL_UNCOMPRESSED_MAX_BYTES {
            return Err(SigningError::Asic(
                "ASiC ZIP members exceed the maximum supported total uncompressed size".to_string(),
            ));
        }

        if index == 0 {
            if name != MIMETYPE_PATH {
                return Err(SigningError::Asic(format!(
                    "ASiC requires the first ZIP member to be mimetype, got {name}"
                )));
            }
            kind = Some(match std::str::from_utf8(&bytes).unwrap_or_default() {
                ASICS_MIMETYPE => AsicContainerKind::AsicS,
                ASICE_MIMETYPE => AsicContainerKind::AsicE,
                other => {
                    return Err(SigningError::Asic(format!(
                        "unsupported ASiC mimetype {other}"
                    )));
                }
            });
            continue;
        }
        members.push((name, bytes));
    }

    let kind = kind
        .ok_or_else(|| SigningError::Asic("ASiC container has no mimetype member".to_string()))?;
    Ok((kind, members))
}

/// Validate one CAdES signature: ASiC-S covers the single payload digest; ASiC-E covers its
/// `ASiCManifest`, whose data-object digests are re-checked against the packaged payloads.
fn validate_cades_signature(
    container_kind: AsicContainerKind,
    path: &str,
    cades_der: &[u8],
    payloads: &[(&str, &[u8])],
    manifest_paths: &[&str],
    members: &[(String, Vec<u8>)],
) -> AsicSignatureValidation {
    let mut failure_reasons = Vec::new();
    let mut covered = Vec::new();
    let mut manifest_path = None;

    let signed_digest: Option<[u8; 32]> = match container_kind {
        AsicContainerKind::AsicS => match payloads {
            [(name, bytes)] => {
                covered.push((*name).to_string());
                Some(sha256_content_digest(bytes))
            }
            _ => {
                failure_reasons.push(format!(
                    "ASiC-S/CAdES requires exactly one payload; found {}",
                    payloads.len()
                ));
                None
            }
        },
        AsicContainerKind::AsicE => {
            match find_manifest_for_signature(path, manifest_paths, members) {
                Some((mpath, mbytes, parsed)) => {
                    manifest_path = Some(mpath.to_string());
                    for reference in &parsed.data_objects {
                        match member(members, &reference.uri) {
                            Some(bytes) if sha256_content_digest(bytes) == reference.digest => {
                                covered.push(reference.uri.clone());
                            }
                            Some(_) => failure_reasons.push(format!(
                                "ASiC-E manifest {mpath} digest mismatch for payload {}",
                                reference.uri
                            )),
                            None => failure_reasons.push(format!(
                                "ASiC-E manifest {mpath} references missing payload {}",
                                reference.uri
                            )),
                        }
                    }
                    Some(sha256_content_digest(&mbytes))
                }
                None => {
                    failure_reasons.push(format!(
                        "ASiC-E/CAdES signature {path} has no ASiCManifest referencing it"
                    ));
                    None
                }
            }
        }
    };

    let mut signer_cert_der = None;
    let mut signing_time = None;
    if let Some(digest) = signed_digest {
        match chancela_cades::validate_cades_b(cades_der, &digest) {
            Ok(validation) => {
                signer_cert_der = Some(validation.signer_cert_der);
                signing_time = validation.signing_time;
            }
            Err(e) => failure_reasons.push(format!("CAdES signature {path} did not verify: {e}")),
        }
    }

    AsicSignatureValidation {
        path: path.to_string(),
        kind: AsicSignatureMemberKind::Cades,
        manifest_path,
        valid: failure_reasons.is_empty() && !covered.is_empty(),
        signer_cert_der,
        signing_time,
        covered_data_objects: covered,
        xades_level: None,
        has_signature_timestamp: false,
        failure_reasons,
    }
}

/// Validate one detached XAdES signature and bind every packaged payload to a signed `ds:Reference`.
fn validate_xades_signature(
    path: &str,
    xml: &[u8],
    payloads: &[(&str, &[u8])],
) -> AsicSignatureValidation {
    let mut failure_reasons = Vec::new();
    let mut covered = Vec::new();
    let mut xades_level = None;
    let mut has_signature_timestamp = false;
    let mut signer_cert_der = None;
    let mut signing_time = None;

    match validate_xades(xml) {
        Ok(report) => {
            xades_level = Some(report.level);
            has_signature_timestamp = report.signature_timestamp_present;
            signer_cert_der = report.signer_cert_der.clone();
            signing_time = report.signing_time;
            if !report.signature_valid {
                failure_reasons.push(format!(
                    "XAdES signature {path} did not verify over SignedInfo"
                ));
            }
            if !report.references_valid {
                failure_reasons.push(format!("XAdES signature {path} has a bad reference digest"));
            }
            if !report.signed_properties_present || !report.signing_certificate_v2_present {
                failure_reasons.push(format!(
                    "XAdES signature {path} is missing XAdES SignedProperties"
                ));
            }

            // Bind each packaged payload to a signed detached reference (the ASiC check a bare-XML
            // validator cannot do). The reference DigestValues live inside the verified SignedInfo,
            // so a match proves the signature commits to this exact payload.
            match parse_xades_reference_digests(xml) {
                Ok(references) => {
                    for (name, bytes) in payloads {
                        match references.iter().find(|(uri, _)| uri == name) {
                            Some((_, digest)) if *digest == sha256_content_digest(bytes) => {
                                covered.push((*name).to_string());
                            }
                            Some(_) => failure_reasons.push(format!(
                                "XAdES signature {path} reference digest mismatch for payload {name}"
                            )),
                            None => failure_reasons.push(format!(
                                "XAdES signature {path} does not reference payload {name}"
                            )),
                        }
                    }
                }
                Err(e) => failure_reasons.push(format!(
                    "XAdES signature {path} references could not be parsed: {e}"
                )),
            }
        }
        Err(e) => failure_reasons.push(format!("XAdES signature {path} did not validate: {e}")),
    }

    AsicSignatureValidation {
        path: path.to_string(),
        kind: AsicSignatureMemberKind::Xades,
        manifest_path: None,
        valid: failure_reasons.is_empty() && !covered.is_empty(),
        signer_cert_der,
        signing_time,
        covered_data_objects: covered,
        xades_level,
        has_signature_timestamp,
        failure_reasons,
    }
}

/// Validate one `ASiCArchiveManifest`: recompute every data-object digest and check the RFC 3161
/// archive-timestamp imprint attests the manifest bytes.
fn validate_archive_manifest(
    path: &str,
    manifest: &[u8],
    members: &[(String, Vec<u8>)],
) -> AsicArchiveTimestampValidation {
    let mut failure_reasons = Vec::new();
    let mut covered = Vec::new();
    let mut references_valid = true;
    let mut imprint_matches_manifest = false;
    let mut gen_time = None;

    let parsed = match parse_asic_manifest(manifest) {
        Ok(parsed) => parsed,
        Err(e) => {
            return AsicArchiveTimestampValidation {
                manifest_path: path.to_string(),
                timestamp_path: String::new(),
                imprint_matches_manifest: false,
                references_valid: false,
                covered_members: Vec::new(),
                gen_time: None,
                valid: false,
                failure_reasons: vec![format!("archive manifest {path} could not be parsed: {e}")],
            };
        }
    };

    for reference in &parsed.data_objects {
        match member(members, &reference.uri) {
            Some(bytes) if sha256_content_digest(bytes) == reference.digest => {
                covered.push(reference.uri.clone());
            }
            Some(_) => {
                references_valid = false;
                failure_reasons.push(format!(
                    "archive manifest {path} digest mismatch for member {}",
                    reference.uri
                ));
            }
            None => {
                references_valid = false;
                failure_reasons.push(format!(
                    "archive manifest {path} references missing member {}",
                    reference.uri
                ));
            }
        }
    }

    let timestamp_path = parsed.signature_uri.clone();
    match member(members, &timestamp_path) {
        Some(token) => match timestamp_token_imprint(token) {
            Ok(imprint) => {
                gen_time = imprint.gen_time;
                imprint_matches_manifest =
                    imprint.hashed_message == sha256_content_digest(manifest);
                if !imprint_matches_manifest {
                    failure_reasons.push(format!(
                        "archive timestamp {timestamp_path} imprint does not attest manifest {path}"
                    ));
                }
            }
            Err(e) => failure_reasons.push(format!(
                "archive timestamp {timestamp_path} could not be parsed: {e}"
            )),
        },
        None => failure_reasons.push(format!(
            "archive manifest {path} references missing timestamp {timestamp_path}"
        )),
    }

    AsicArchiveTimestampValidation {
        manifest_path: path.to_string(),
        timestamp_path,
        imprint_matches_manifest,
        references_valid,
        covered_members: covered,
        gen_time,
        valid: failure_reasons.is_empty() && imprint_matches_manifest && references_valid,
        failure_reasons,
    }
}

fn diagnose_embedded_evidence(
    members: &[(String, Vec<u8>)],
    xades_paths: &[&str],
    archive_timestamps: &[AsicArchiveTimestampValidation],
) -> (
    Vec<AsicEmbeddedEvidenceIndicator>,
    Vec<AsicEmbeddedEvidenceBlocker>,
) {
    let mut indicators = Vec::new();
    let mut blockers = Vec::new();

    for path in xades_paths {
        let Some(xml) = member(members, path) else {
            continue;
        };
        diagnose_xades_embedded_evidence(path, xml, &mut indicators, &mut blockers);
    }

    for archive in archive_timestamps {
        indicators.push(AsicEmbeddedEvidenceIndicator {
            code: "asic_archive_timestamp_manifest".to_string(),
            source_path: archive.manifest_path.clone(),
            evidence_kind: "lta_evidence".to_string(),
            message: format!(
                "ASiCArchiveManifest references local timestamp token {}",
                archive.timestamp_path
            ),
        });
        if archive.valid {
            indicators.push(AsicEmbeddedEvidenceIndicator {
                code: "asic_archive_timestamp_valid_local".to_string(),
                source_path: archive.timestamp_path.clone(),
                evidence_kind: "lta_evidence".to_string(),
                message: "archive timestamp imprint and referenced member digests matched locally"
                    .to_string(),
            });
        } else {
            blockers.push(AsicEmbeddedEvidenceBlocker {
                code: "asic_archive_timestamp_invalid_local".to_string(),
                source_path: archive.manifest_path.clone(),
                message: if archive.failure_reasons.is_empty() {
                    "archive timestamp evidence is not locally consistent".to_string()
                } else {
                    archive.failure_reasons.join("; ")
                },
            });
        }
    }

    for (path, _) in members
        .iter()
        .filter(|(path, _)| is_timestamp_token_path(path))
    {
        let referenced = archive_timestamps
            .iter()
            .any(|archive| archive.timestamp_path == *path);
        if !referenced {
            blockers.push(AsicEmbeddedEvidenceBlocker {
                code: "unreferenced_timestamp_token_member".to_string(),
                source_path: path.clone(),
                message:
                    "timestamp token member is present but no ASiCArchiveManifest references it"
                        .to_string(),
            });
        }
    }

    (indicators, blockers)
}

fn diagnose_xades_embedded_evidence(
    path: &str,
    xml: &[u8],
    indicators: &mut Vec<AsicEmbeddedEvidenceIndicator>,
    blockers: &mut Vec<AsicEmbeddedEvidenceBlocker>,
) {
    let text = match std::str::from_utf8(xml) {
        Ok(text) => text,
        Err(_) => {
            blockers.push(AsicEmbeddedEvidenceBlocker {
                code: "xades_embedded_evidence_xml_unreadable".to_string(),
                source_path: path.to_string(),
                message:
                    "XAdES member is not UTF-8, so embedded LT/LTA indicators were not inspected"
                        .to_string(),
            });
            return;
        }
    };
    let doc = match roxmltree::Document::parse(text) {
        Ok(doc) => doc,
        Err(e) => {
            blockers.push(AsicEmbeddedEvidenceBlocker {
                code: "xades_embedded_evidence_xml_malformed".to_string(),
                source_path: path.to_string(),
                message: format!(
                    "XAdES member is malformed XML, so embedded LT/LTA indicators were not inspected: {e}"
                ),
            });
            return;
        }
    };

    let signature_timestamp_count = count_elements(&doc, "SignatureTimeStamp");
    let complete_certificate_refs = count_elements(&doc, "CompleteCertificateRefs");
    let complete_revocation_refs = count_elements(&doc, "CompleteRevocationRefs");
    let certificate_values = count_elements(&doc, "CertificateValues");
    let revocation_values = count_elements(&doc, "RevocationValues");
    let ocsp_values = count_elements(&doc, "OCSPValues");
    let crl_values = count_elements(&doc, "CRLValues");
    let archive_timestamp_count = count_elements(&doc, "ArchiveTimeStamp")
        + count_elements(&doc, "SigAndRefsTimeStamp")
        + count_elements(&doc, "RefsOnlyTimeStamp");

    if signature_timestamp_count > 0 {
        indicators.push(AsicEmbeddedEvidenceIndicator {
            code: "xades_signature_timestamp".to_string(),
            source_path: path.to_string(),
            evidence_kind: "signature_timestamp".to_string(),
            message: format!(
                "XAdES member contains {signature_timestamp_count} SignatureTimeStamp element(s)"
            ),
        });
    }
    if complete_certificate_refs > 0 {
        indicators.push(AsicEmbeddedEvidenceIndicator {
            code: "xades_certificate_refs".to_string(),
            source_path: path.to_string(),
            evidence_kind: "lt_evidence".to_string(),
            message: format!(
                "XAdES member contains {complete_certificate_refs} CompleteCertificateRefs element(s)"
            ),
        });
    }
    if complete_revocation_refs > 0 {
        indicators.push(AsicEmbeddedEvidenceIndicator {
            code: "xades_revocation_refs".to_string(),
            source_path: path.to_string(),
            evidence_kind: "lt_evidence".to_string(),
            message: format!(
                "XAdES member contains {complete_revocation_refs} CompleteRevocationRefs element(s)"
            ),
        });
    }
    if certificate_values > 0 {
        indicators.push(AsicEmbeddedEvidenceIndicator {
            code: "xades_certificate_values".to_string(),
            source_path: path.to_string(),
            evidence_kind: "lt_evidence".to_string(),
            message: format!(
                "XAdES member contains {certificate_values} CertificateValues element(s)"
            ),
        });
    }
    if revocation_values > 0 || ocsp_values > 0 || crl_values > 0 {
        indicators.push(AsicEmbeddedEvidenceIndicator {
            code: "xades_revocation_values".to_string(),
            source_path: path.to_string(),
            evidence_kind: "lt_evidence".to_string(),
            message: format!(
                "XAdES member contains revocation-value elements: RevocationValues={revocation_values}, OCSPValues={ocsp_values}, CRLValues={crl_values}"
            ),
        });
    }
    if archive_timestamp_count > 0 {
        indicators.push(AsicEmbeddedEvidenceIndicator {
            code: "xades_archive_timestamp".to_string(),
            source_path: path.to_string(),
            evidence_kind: "lta_evidence".to_string(),
            message: format!(
                "XAdES member contains {archive_timestamp_count} archive timestamp element(s)"
            ),
        });
    }

    let has_lt_like = complete_certificate_refs > 0
        || complete_revocation_refs > 0
        || certificate_values > 0
        || revocation_values > 0
        || ocsp_values > 0
        || crl_values > 0;
    if has_lt_like && signature_timestamp_count == 0 {
        blockers.push(AsicEmbeddedEvidenceBlocker {
            code: "xades_lt_material_without_signature_timestamp".to_string(),
            source_path: path.to_string(),
            message: "LT-like XAdES material is present, but no local SignatureTimeStamp element was found"
                .to_string(),
        });
    }
    if has_lt_like
        && (certificate_values == 0 || (revocation_values + ocsp_values + crl_values) == 0)
    {
        blockers.push(AsicEmbeddedEvidenceBlocker {
            code: "xades_lt_values_incomplete".to_string(),
            source_path: path.to_string(),
            message: "LT-like XAdES material is present, but local certificate or revocation value elements are incomplete"
                .to_string(),
        });
    }
    if archive_timestamp_count > 0 && signature_timestamp_count == 0 {
        blockers.push(AsicEmbeddedEvidenceBlocker {
            code: "xades_archive_timestamp_without_signature_timestamp".to_string(),
            source_path: path.to_string(),
            message: "LTA-like XAdES archive timestamp is present, but no local SignatureTimeStamp element was found"
                .to_string(),
        });
    }
    if archive_timestamp_count > 0 && !has_lt_like {
        blockers.push(AsicEmbeddedEvidenceBlocker {
            code: "xades_archive_timestamp_without_lt_material".to_string(),
            source_path: path.to_string(),
            message: "LTA-like XAdES archive timestamp is present, but no local LT-like certificate or revocation material was found"
                .to_string(),
        });
    }
}

fn count_elements(doc: &roxmltree::Document<'_>, local_name: &str) -> usize {
    doc.descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == local_name)
        .count()
}

/// The `ASiCManifest` whose `SigReference` names `signature_path`, plus its bytes and parse.
fn find_manifest_for_signature<'a>(
    signature_path: &str,
    manifest_paths: &[&'a str],
    members: &[(String, Vec<u8>)],
) -> Option<(&'a str, Vec<u8>, ParsedManifest)> {
    for mpath in manifest_paths {
        let bytes = member(members, mpath)?;
        if let Ok(parsed) = parse_asic_manifest(bytes) {
            if parsed.signature_uri == signature_path {
                return Some((mpath, bytes.to_vec(), parsed));
            }
        }
    }
    None
}

#[derive(Debug)]
struct ParsedManifest {
    signature_uri: String,
    data_objects: Vec<ParsedManifestReference>,
}

#[derive(Debug)]
struct ParsedManifestReference {
    uri: String,
    digest: [u8; 32],
}

/// Parse an `asic:ASiCManifest` (used for both per-signature and archive manifests) into its
/// `SigReference` URI and the `DataObjectReference` (URI, SHA-256 digest) pairs.
fn parse_asic_manifest(bytes: &[u8]) -> Result<ParsedManifest, SigningError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| SigningError::Asic("ASiC manifest is not UTF-8".to_string()))?;
    let doc = roxmltree::Document::parse(text)
        .map_err(|e| SigningError::Asic(format!("ASiC manifest is malformed XML: {e}")))?;

    let signature_uri = doc
        .descendants()
        .find(|n| n.has_tag_name((ASIC_NS, "SigReference")))
        .and_then(|n| n.attribute("URI"))
        .ok_or_else(|| SigningError::Asic("ASiC manifest has no SigReference".to_string()))?
        .to_string();

    let mut data_objects = Vec::new();
    for node in doc
        .descendants()
        .filter(|n| n.has_tag_name((ASIC_NS, "DataObjectReference")))
    {
        let uri = node
            .attribute("URI")
            .ok_or_else(|| {
                SigningError::Asic("ASiC manifest DataObjectReference has no URI".to_string())
            })?
            .to_string();
        let digest_b64: String = node
            .descendants()
            .find(|n| n.has_tag_name((DS_NS, "DigestValue")))
            .and_then(|n| n.text())
            .ok_or_else(|| {
                SigningError::Asic(
                    "ASiC manifest DataObjectReference has no DigestValue".to_string(),
                )
            })?
            .split_whitespace()
            .collect();
        let digest = decode_sha256_b64(&digest_b64)?;
        data_objects.push(ParsedManifestReference { uri, digest });
    }
    if data_objects.is_empty() {
        return Err(SigningError::Asic(
            "ASiC manifest has no DataObjectReference entries".to_string(),
        ));
    }

    Ok(ParsedManifest {
        signature_uri,
        data_objects,
    })
}

/// Parse the `ds:SignedInfo/ds:Reference` (URI, SHA-256 digest) pairs from a XAdES document.
fn parse_xades_reference_digests(xml: &[u8]) -> Result<Vec<(String, [u8; 32])>, SigningError> {
    let text = std::str::from_utf8(xml)
        .map_err(|_| SigningError::Xades("XAdES document is not UTF-8".to_string()))?;
    let doc = roxmltree::Document::parse(text)
        .map_err(|e| SigningError::Xades(format!("XAdES document is malformed XML: {e}")))?;

    let signed_info = doc
        .descendants()
        .find(|n| n.has_tag_name((DS_NS, "SignedInfo")))
        .ok_or_else(|| SigningError::Xades("XAdES has no SignedInfo".to_string()))?;

    let mut refs = Vec::new();
    for reference in signed_info
        .children()
        .filter(|n| n.has_tag_name((DS_NS, "Reference")))
    {
        let Some(uri) = reference.attribute("URI") else {
            continue;
        };
        if uri.is_empty() || uri.starts_with('#') {
            // Enveloped / same-document (e.g. the SignedProperties) references are not payloads.
            continue;
        }
        let digest_b64: String = reference
            .descendants()
            .find(|n| n.has_tag_name((DS_NS, "DigestValue")))
            .and_then(|n| n.text())
            .ok_or_else(|| SigningError::Xades("XAdES Reference has no DigestValue".to_string()))?
            .split_whitespace()
            .collect();
        refs.push((uri.to_string(), decode_sha256_b64(&digest_b64)?));
    }
    Ok(refs)
}

fn decode_sha256_b64(b64: &str) -> Result<[u8; 32], SigningError> {
    BASE64_STANDARD
        .decode(b64.as_bytes())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| SigningError::Asic("DigestValue is not a base64 SHA-256 digest".to_string()))
}

#[derive(Debug)]
struct TokenImprint {
    hashed_message: [u8; 32],
    gen_time: Option<OffsetDateTime>,
}

/// Extract the RFC 3161 message imprint (and genTime) from an archive-timestamp token, mirroring the
/// imprint-only read `chancela-pades` uses for `/DocTimeStamp` (TSA trust is a separate job).
fn timestamp_token_imprint(token_der: &[u8]) -> Result<TokenImprint, SigningError> {
    let ci = ContentInfo::from_der(token_der).map_err(|_| {
        SigningError::Asic("archive timestamp is not a CMS ContentInfo".to_string())
    })?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(SigningError::Asic(
            "archive timestamp is not CMS SignedData".to_string(),
        ));
    }
    let signed_data_der = ci
        .content
        .to_der()
        .map_err(|_| SigningError::Asic("archive timestamp SignedData is malformed".to_string()))?;
    let signed_data = SignedData::from_der(&signed_data_der)
        .map_err(|_| SigningError::Asic("archive timestamp SignedData is malformed".to_string()))?;
    if signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(SigningError::Asic(
            "archive timestamp does not encapsulate a TSTInfo".to_string(),
        ));
    }
    let tst_der = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| SigningError::Asic("archive timestamp has empty TSTInfo".to_string()))?
        .value();
    let tst = x509_tsp::TstInfo::from_der(tst_der)
        .map_err(|_| SigningError::Asic("archive timestamp TSTInfo is malformed".to_string()))?;
    if tst.message_imprint.hash_algorithm.oid != ID_SHA256 {
        return Err(SigningError::Asic(
            "archive timestamp imprint is not SHA-256".to_string(),
        ));
    }
    let hashed_message = <[u8; 32]>::try_from(tst.message_imprint.hashed_message.as_bytes())
        .map_err(|_| SigningError::Asic("archive timestamp imprint is not 32 bytes".to_string()))?;
    let gen_time = OffsetDateTime::from_unix_timestamp(
        i64::try_from(tst.gen_time.to_unix_duration().as_secs()).unwrap_or_default(),
    )
    .ok();

    Ok(TokenImprint {
        hashed_message,
        gen_time,
    })
}
