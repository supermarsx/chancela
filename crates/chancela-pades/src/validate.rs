//! Structural + delegated validation of a signed PDF (SIG-24).
//!
//! Locate the `/Sig` dictionary, recompute the `/ByteRange` digest over the raw file bytes, and
//! hand the embedded CMS to `chancela_cades::validate_cades_b` for the cryptographic check. Trust
//! and qualified-status decisions belong to `chancela-tsl` / `chancela-signing`, not here.

use std::collections::BTreeSet;

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::Decode;
use der::asn1::ObjectIdentifier;
use sha2::{Digest, Sha256};

use crate::archive_timestamp::{self, DocTimeStampReport};
use crate::dss::{self, DssReport};
use crate::error::PadesError;
use crate::pdf;
use crate::renewal::{
    self, LtvRenewalPlan, MultiSignatureLtvRenewalPlan, SignatureRenewalEvidence,
};

/// OID `id-aa-signatureTimeStampToken` — presence of this unsigned attribute marks a B-T signature.
const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// How much of the PDF a validated PAdES signature actually covers (SIG-24, finding C3).
///
/// A PAdES signature only ever digests the byte ranges named by its `/ByteRange`. A PDF can carry
/// incremental updates appended *after* the signed revision; `lopdf` (like any viewer) renders the
/// latest revision, so the displayed document can differ from the bytes the signature covered. This
/// enum is the authoritative coverage verdict a caller must consult before reporting a signature as
/// valid: only [`PdfSignatureCoverage::WholeDocument`] and
/// [`PdfSignatureCoverage::LtvAugmentedSignedRevision`] mean the signature vouches for what is
/// rendered. Gate on [`PdfSignatureCoverage::covers_rendered_document`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PdfSignatureCoverage {
    /// The `/ByteRange` starts at byte 0, excludes exactly the `/Contents` value, and reaches the
    /// end of the file. No incremental update follows the signed revision — the whole document as
    /// rendered is covered.
    WholeDocument,
    /// The signature covers its own revision cleanly (starts at byte 0, excludes exactly the
    /// `/Contents` value), and every incremental update appended afterwards is benign PAdES
    /// long-term-validation material: a `/DSS` revision (its dictionary, `/VRI`, and evidence
    /// streams) and/or a `/DocTimeStamp` and its form field, with the catalog/AcroForm changes
    /// limited to wiring that evidence in. Such updates cannot change the displayed document, so the
    /// signature still vouches for what is rendered.
    LtvAugmentedSignedRevision,
    /// The signature covers only its own revision, and at least one incremental update appended
    /// afterwards changes an object that can alter the rendered document (a page, the page tree, an
    /// annotation, a second signature, an unconstrained catalog/AcroForm change) — or the later
    /// updates could not be proven benign. The displayed document may differ from what was signed;
    /// the signature does NOT vouch for it. This is the incremental-update tamper case (C3).
    AlteredAfterSigning,
    /// The `/ByteRange` cannot support a coverage claim at all: it does not begin at byte 0, or the
    /// excluded gap is not exactly the `/Contents` string (so bytes outside `/Contents` were left
    /// unsigned). The signature must not be reported as covering the document even if the embedded
    /// CMS digest verifies.
    Malformed,
}

impl PdfSignatureCoverage {
    /// Whether the signature can be reported as covering the rendered document. `true` only for
    /// [`Self::WholeDocument`] and [`Self::LtvAugmentedSignedRevision`]. **This is the gate the API
    /// status mapping must honor**: a signature whose CMS verifies but whose coverage is
    /// [`Self::AlteredAfterSigning`] or [`Self::Malformed`] must not be reported as `Valid`.
    pub fn covers_rendered_document(self) -> bool {
        matches!(self, Self::WholeDocument | Self::LtvAugmentedSignedRevision)
    }
}

/// A report from validating a PAdES signature (SIG-24).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PdfSignatureReport {
    /// The `/ByteRange` array as `[start1, len1, start2, len2]`.
    pub byte_range: [i64; 4],
    /// Number of bytes actually covered by the signature (`len1 + len2`).
    pub covered_len: usize,
    /// Total size of the signed PDF.
    pub total_len: usize,
    /// End offset of the signed revision (`ByteRange[2] + ByteRange[3]`). Later incremental
    /// updates, such as a DSS revision, may start after this offset.
    pub signed_revision_len: usize,
    /// Authoritative coverage verdict (SIG-24, finding C3). Callers that map this report to a
    /// validity status **must** gate on [`PdfSignatureCoverage::covers_rendered_document`]: a
    /// verified CMS with [`PdfSignatureCoverage::AlteredAfterSigning`] or
    /// [`PdfSignatureCoverage::Malformed`] coverage must not be reported as valid, because the
    /// rendered document differs from (or is not fully bound by) the signed bytes.
    pub coverage: PdfSignatureCoverage,
    /// Whether the ByteRange starts at 0, excludes exactly the `/Contents` value, and extends to
    /// the end of the file — the well-formed whole-document PAdES shape. Equivalent to
    /// `coverage == PdfSignatureCoverage::WholeDocument`.
    pub covers_whole_file_except_contents: bool,
    /// Whether the ByteRange starts at 0 and excludes exactly the `/Contents` value of the signed
    /// revision. This remains true when a later incremental update appends caller-supplied DSS
    /// evidence. It does **not** by itself distinguish benign LTV augmentation from a
    /// content-bearing (tampering) incremental update — consult [`Self::coverage`] for that.
    pub covers_signed_revision_except_contents: bool,
    /// Whether bytes exist after the signed revision, usually from a later incremental update.
    pub has_later_incremental_updates: bool,
    /// The delegated CAdES validation result (signature verified, attributes consistent).
    pub cades: chancela_cades::CadesValidation,
    /// Whether an `id-aa-signatureTimeStampToken` unsigned attribute is present (PAdES-B-T).
    pub has_signature_timestamp: bool,
    /// Embedded DSS/VRI evidence report from the latest PDF catalog.
    pub dss: DssReport,
    /// Embedded document timestamp report. Presence is a technical fact, not a B-LTA claim.
    pub doc_timestamps: DocTimeStampReport,
    /// Local technical LTV renewal planning summary. This is not a B-LT/B-LTA/legal LTV claim.
    pub ltv_renewal_plan: LtvRenewalPlan,
    /// Local technical renewal planning for every discovered `/Sig` dictionary.
    ///
    /// This is coverage reporting only. It does not validate every signature cryptographically and
    /// does not make a B-LT/B-LTA/legal LTV claim.
    pub multi_signature_ltv_renewal_plan: MultiSignatureLtvRenewalPlan,
}

/// Validate the (first) PAdES signature in `pdf` (SIG-24).
///
/// Returns `Err` if there is no signature, the `/ByteRange` is malformed, the `/Contents` is not a
/// well-formed CMS, or the embedded CAdES signature fails to verify against the recomputed digest.
pub fn validate_pdf_signature(pdf: &[u8]) -> Result<PdfSignatureReport, PadesError> {
    let doc = lopdf::Document::load_mem(pdf).map_err(|e| PadesError::PdfParse(e.to_string()))?;

    let signatures = signature_dictionaries(&doc);
    let sig = signatures
        .first()
        .map(|(_, dict)| *dict)
        .ok_or(PadesError::NoSignature)?;

    // /ByteRange = [start1 len1 start2 len2].
    let br_arr = sig
        .get(b"ByteRange")
        .and_then(lopdf::Object::as_array)
        .map_err(|_| PadesError::InvalidByteRange)?;
    if br_arr.len() != 4 {
        return Err(PadesError::InvalidByteRange);
    }
    let mut byte_range = [0i64; 4];
    for (i, o) in br_arr.iter().enumerate() {
        byte_range[i] = o.as_i64().map_err(|_| PadesError::InvalidByteRange)?;
    }

    let total = pdf.len();
    let [s1, l1, s2, l2] = byte_range;
    let (s1, l1, s2, l2) = (usize_of(s1)?, usize_of(l1)?, usize_of(s2)?, usize_of(l2)?);
    // Bounds: both ranges must lie inside the file.
    if s1.checked_add(l1).map(|e| e > total).unwrap_or(true)
        || s2.checked_add(l2).map(|e| e > total).unwrap_or(true)
    {
        return Err(PadesError::InvalidByteRange);
    }

    // Recompute the digest over the covered bytes of the *raw* file.
    let mut hasher = Sha256::new();
    hasher.update(&pdf[s1..s1 + l1]);
    hasher.update(&pdf[s2..s2 + l2]);
    let content_digest: [u8; 32] = hasher.finalize().into();

    let covered_len = l1 + l2;
    let signed_revision_len = s2 + l2;

    // Coverage requires that the *only* bytes excluded from the digest are the `/Contents` value.
    // Checking `s1 == 0 && s1 + l1 <= s2` alone is not enough: a crafted ByteRange whose gap spans
    // more than `/Contents` would leave content bytes unsigned yet still verify. Assert the excluded
    // gap `[s1+l1, s2)` is byte-for-byte the `/Contents` hex-string token.
    let contents_full = sig
        .get(b"Contents")
        .and_then(lopdf::Object::as_str)
        .map_err(|_| PadesError::InvalidContents)?;
    let gap_is_exactly_contents = s1 == 0 && gap_matches_contents(pdf, s1 + l1, s2, contents_full);
    let covers_signed_revision_except_contents = gap_is_exactly_contents;
    let covers_whole_file_except_contents =
        covers_signed_revision_except_contents && signed_revision_len == total;
    let has_later_incremental_updates = signed_revision_len < total;

    // Classify what the excluded gap and any later incremental updates mean for coverage. The API
    // status mapping gates on this (see `PdfSignatureCoverage::covers_rendered_document`).
    let coverage = if !gap_is_exactly_contents {
        PdfSignatureCoverage::Malformed
    } else if !has_later_incremental_updates {
        PdfSignatureCoverage::WholeDocument
    } else {
        match classify_later_updates(&doc, &pdf[..signed_revision_len]) {
            LaterUpdateClass::LtvAugmentationOnly => {
                PdfSignatureCoverage::LtvAugmentedSignedRevision
            }
            LaterUpdateClass::NotProvenBenign => PdfSignatureCoverage::AlteredAfterSigning,
        }
    };

    // /Contents (lopdf gives the hex-decoded bytes; trim trailing zero padding to the DER length).
    let cms_der = signature_contents_der(sig)?;

    // Delegate the cryptographic + attribute check to chancela-cades.
    let cades = chancela_cades::validate_cades_b(cms_der, &content_digest)?;

    let has_signature_timestamp = detect_signature_timestamp(cms_der).unwrap_or(false);
    let dss = dss::inspect_dss_document(&doc)?;
    let doc_timestamps = archive_timestamp::inspect_doc_timestamps_document(&doc, pdf)?;
    let ltv_renewal_plan =
        renewal::plan_ltv_renewal(has_signature_timestamp, &dss, &doc_timestamps);
    let signature_renewal_evidence = signature_renewal_evidence(&signatures);
    let multi_signature_ltv_renewal_plan = renewal::plan_multi_signature_ltv_renewal(
        signature_renewal_evidence,
        &dss,
        &doc_timestamps,
        renewal::LtvRenewalPolicy::default(),
    );

    Ok(PdfSignatureReport {
        byte_range,
        covered_len,
        total_len: total,
        signed_revision_len,
        coverage,
        covers_whole_file_except_contents,
        covers_signed_revision_except_contents,
        has_later_incremental_updates,
        cades,
        has_signature_timestamp,
        dss,
        doc_timestamps,
        ltv_renewal_plan,
        multi_signature_ltv_renewal_plan,
    })
}

/// Whether the excluded ByteRange gap `pdf[gap_start..gap_end)` is byte-for-byte the `/Contents`
/// hex-string token — i.e. a single `<...>` whose hex decodes to exactly `contents` and nothing
/// else. This is what makes "the signature covers everything except `/Contents`" true: if the gap
/// were larger than `/Contents`, unsigned content bytes would sit in the hole (finding C3 MEDIUM).
fn gap_matches_contents(pdf: &[u8], gap_start: usize, gap_end: usize, contents: &[u8]) -> bool {
    if gap_end <= gap_start || gap_end > pdf.len() {
        return false;
    }
    let gap = &pdf[gap_start..gap_end];
    // The gap must be exactly one PDF hexadecimal string token: '<' … '>'.
    if gap.first() != Some(&b'<') || gap.last() != Some(&b'>') {
        return false;
    }
    let inner = &gap[1..gap.len() - 1];
    let mut decoded = Vec::with_capacity(inner.len() / 2 + 1);
    let mut hi: Option<u8> = None;
    for &b in inner {
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            // PDF hex strings ignore embedded whitespace.
            b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\0' => continue,
            // Any other byte (notably a nested '<' or '>') means the gap is not a lone token.
            _ => return false,
        };
        match hi.take() {
            None => hi = Some(nibble),
            Some(high) => decoded.push((high << 4) | nibble),
        }
    }
    // A trailing odd nibble is padded with 0 (PDF hex-string rule), matching lopdf's decoding.
    if let Some(high) = hi {
        decoded.push(high << 4);
    }
    decoded == contents
}

/// Classification of the incremental update(s) appended after the signed revision.
enum LaterUpdateClass {
    /// Every added/modified object is benign PAdES LTV augmentation (a `/DSS` revision and/or a
    /// `/DocTimeStamp`), so the rendered document is unchanged from the signed revision.
    LtvAugmentationOnly,
    /// At least one added/modified object is content-bearing, or the later updates could not be
    /// proven benign (the signed revision did not re-parse as a standalone PDF). Fails closed.
    NotProvenBenign,
}

/// Diff the object graph of the whole file against the signed revision on its own, and decide
/// whether the later incremental update(s) are benign LTV augmentation or content-bearing (C3).
///
/// `signed_revision` is `pdf[..signed_revision_len]` — the exact bytes the first signature covers,
/// which is a self-contained PDF ending at its own `%%EOF`. Any object that is new or changed in the
/// full document relative to that revision must fall inside a tight allowlist of DSS/DocTimeStamp
/// wiring; anything else (a redefined page, page tree, annotation, or an unconstrained
/// catalog/AcroForm change) is content-bearing and breaks the coverage claim.
fn classify_later_updates(full: &lopdf::Document, signed_revision: &[u8]) -> LaterUpdateClass {
    let Ok(base) = lopdf::Document::load_mem(signed_revision) else {
        // Cannot establish what the signed revision contained; do not claim the later bytes benign.
        return LaterUpdateClass::NotProvenBenign;
    };

    let mut changed: Vec<(u32, u16)> = Vec::new();
    for (id, obj) in &full.objects {
        match base.objects.get(id) {
            Some(prev) if prev == obj => {}
            _ => changed.push(*id),
        }
    }
    if changed.is_empty() {
        // Trailing bytes but no object added or modified (e.g. only a new xref/trailer): benign.
        return LaterUpdateClass::LtvAugmentationOnly;
    }

    let benign = benign_ltv_object_ids(full, &base);
    if changed.iter().all(|id| benign.contains(id)) {
        LaterUpdateClass::LtvAugmentationOnly
    } else {
        LaterUpdateClass::NotProvenBenign
    }
}

/// The set of object ids in `full` that a later incremental update is allowed to add or modify while
/// staying benign PAdES LTV augmentation: the `/DSS` dictionary, its `/VRI` dictionary and entries,
/// its evidence streams, every `/DocTimeStamp` dictionary and its `/Sig` form field, and — only when
/// their change is constrained to wiring that evidence in — the catalog and the AcroForm.
fn benign_ltv_object_ids(full: &lopdf::Document, base: &lopdf::Document) -> BTreeSet<(u32, u16)> {
    let mut benign = BTreeSet::new();

    let Ok(root_id) = full
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
    else {
        return benign;
    };
    let Ok(catalog) = full.get_object(root_id).and_then(lopdf::Object::as_dict) else {
        return benign;
    };

    // --- DSS revision: the dictionary, its VRI (and per-signature entries) and evidence streams ---
    if let Ok(dss_ref) = catalog.get(b"DSS").and_then(lopdf::Object::as_reference) {
        benign.insert(dss_ref);
        if let Ok(dss) = full.get_object(dss_ref).and_then(lopdf::Object::as_dict) {
            if let Ok(vri_ref) = dss.get(b"VRI").and_then(lopdf::Object::as_reference) {
                benign.insert(vri_ref);
                if let Ok(vri) = full.get_object(vri_ref).and_then(lopdf::Object::as_dict) {
                    collect_vri_entry_refs(vri, &mut benign);
                }
            } else if let Ok(vri) = dss.get(b"VRI").and_then(lopdf::Object::as_dict) {
                collect_vri_entry_refs(vri, &mut benign);
            }
            for key in [b"Certs".as_slice(), b"OCSPs", b"CRLs"] {
                if let Ok(arr) = dss.get(key).and_then(lopdf::Object::as_array) {
                    for item in arr {
                        if let Ok(entry) = item.as_reference() {
                            benign.insert(entry);
                        }
                    }
                }
            }
        }
        // The catalog itself counts as benign only if its sole change is wiring in `/DSS`.
        if let Some(base_catalog) = document_catalog(base) {
            if catalog_change_is_dss_only(base_catalog, catalog) {
                benign.insert(root_id);
            }
        }
    }

    // --- DocTimeStamp revision: every `/DocTimeStamp` dictionary and its `/Sig` form field ---
    for (id, obj) in &full.objects {
        if let Ok(dict) = obj.as_dict() {
            if dict
                .get_type()
                .map(|ty| ty == b"DocTimeStamp")
                .unwrap_or(false)
                || is_doc_timestamp_field(full, dict)
            {
                benign.insert(*id);
            }
        }
    }
    // …and the AcroForm that lists those fields, only if it changed nothing but `/Fields`/`/SigFlags`.
    if let Ok(acroform_ref) = catalog
        .get(b"AcroForm")
        .and_then(lopdf::Object::as_reference)
    {
        if let (Ok(full_acroform), Some(base_acroform)) = (
            full.get_object(acroform_ref)
                .and_then(lopdf::Object::as_dict),
            document_acroform(base),
        ) {
            if acroform_change_is_field_list_only(base_acroform, full_acroform) {
                benign.insert(acroform_ref);
            }
        }
    }

    benign
}

/// Add every indirect VRI entry dictionary referenced by a `/DSS /VRI` dictionary.
fn collect_vri_entry_refs(vri: &lopdf::Dictionary, benign: &mut BTreeSet<(u32, u16)>) {
    for (_, item) in vri.iter() {
        if let Ok(entry) = item.as_reference() {
            benign.insert(entry);
        }
    }
}

/// The `/Root` catalog dictionary of `doc`, if resolvable.
fn document_catalog(doc: &lopdf::Document) -> Option<&lopdf::Dictionary> {
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .ok()?;
    doc.get_object(root).and_then(lopdf::Object::as_dict).ok()
}

/// The catalog's `/AcroForm` dictionary of `doc`, if resolvable.
fn document_acroform(doc: &lopdf::Document) -> Option<&lopdf::Dictionary> {
    let acroform = document_catalog(doc)?
        .get(b"AcroForm")
        .and_then(lopdf::Object::as_reference)
        .ok()?;
    doc.get_object(acroform)
        .and_then(lopdf::Object::as_dict)
        .ok()
}

/// Whether the only difference between the base and full catalog is the addition/change of `/DSS`.
/// Any other changed, added, or removed key means the catalog carries a content change (e.g. a
/// redefined `/Pages` tree — the canonical C3 tamper).
fn catalog_change_is_dss_only(
    base_catalog: &lopdf::Dictionary,
    full_catalog: &lopdf::Dictionary,
) -> bool {
    for (key, value) in full_catalog.iter() {
        if key.as_slice() == b"DSS" {
            continue;
        }
        match base_catalog.get(key.as_slice()) {
            Ok(base_value) if base_value == value => {}
            _ => return false,
        }
    }
    for (key, _) in base_catalog.iter() {
        if key.as_slice() != b"DSS" && full_catalog.get(key.as_slice()).is_err() {
            return false;
        }
    }
    true
}

/// Whether the only differences between the base and full AcroForm are the `/Fields` list and
/// `/SigFlags` (what a `/DocTimeStamp` append touches). Newly referenced field objects are vetted
/// separately by the object diff, so an injected content field surfaces there, not here.
fn acroform_change_is_field_list_only(
    base_acroform: &lopdf::Dictionary,
    full_acroform: &lopdf::Dictionary,
) -> bool {
    for (key, value) in full_acroform.iter() {
        match key.as_slice() {
            b"Fields" | b"SigFlags" => {}
            other => match base_acroform.get(other) {
                Ok(base_value) if base_value == value => {}
                _ => return false,
            },
        }
    }
    for (key, _) in base_acroform.iter() {
        match key.as_slice() {
            b"Fields" | b"SigFlags" => {}
            other => {
                if full_acroform.get(other).is_err() {
                    return false;
                }
            }
        }
    }
    true
}

/// Whether `dict` is a `/Sig` form field whose `/V` value resolves to a `/DocTimeStamp` dictionary
/// (the field a `/DocTimeStamp` incremental update appends). The original signature's field points
/// at a `/Type /Sig` dictionary and so does not match.
fn is_doc_timestamp_field(doc: &lopdf::Document, dict: &lopdf::Dictionary) -> bool {
    let is_sig_field = dict
        .get(b"FT")
        .and_then(lopdf::Object::as_name)
        .map(|name| name == b"Sig")
        .unwrap_or(false);
    if !is_sig_field {
        return false;
    }
    let Ok(value_ref) = dict.get(b"V").and_then(lopdf::Object::as_reference) else {
        return false;
    };
    doc.get_object(value_ref)
        .and_then(lopdf::Object::as_dict)
        .map(|value| {
            value
                .get_type()
                .map(|ty| ty == b"DocTimeStamp")
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn signature_dictionaries(doc: &lopdf::Document) -> Vec<((u32, u16), &lopdf::Dictionary)> {
    let mut signatures: Vec<_> = doc
        .objects
        .iter()
        .filter_map(|(id, obj)| {
            let dict = obj.as_dict().ok()?;
            dict.get_type().ok().filter(|ty| *ty == b"Sig")?;
            Some((*id, dict))
        })
        .collect();
    signatures.sort_by_key(|(id, _)| *id);
    signatures
}

fn signature_renewal_evidence(
    signatures: &[((u32, u16), &lopdf::Dictionary)],
) -> Vec<SignatureRenewalEvidence> {
    signatures
        .iter()
        .enumerate()
        .filter_map(|(index, (object_id, dict))| {
            let cms_der = signature_contents_der(dict).ok()?;
            Some(SignatureRenewalEvidence {
                index,
                object_id: *object_id,
                signed_revision_len: signed_revision_len(dict)?,
                vri_key: pdf::to_hex(&Sha256::digest(cms_der)),
                signature_timestamp_present: detect_signature_timestamp(cms_der).unwrap_or(false),
            })
        })
        .collect()
}

fn signature_contents_der(sig: &lopdf::Dictionary) -> Result<&[u8], PadesError> {
    let contents = sig
        .get(b"Contents")
        .and_then(lopdf::Object::as_str)
        .map_err(|_| PadesError::InvalidContents)?;
    let der_len = pdf::der_total_len(contents).ok_or(PadesError::InvalidContents)?;
    if der_len > contents.len() {
        return Err(PadesError::InvalidContents);
    }
    Ok(&contents[..der_len])
}

fn signed_revision_len(sig: &lopdf::Dictionary) -> Option<usize> {
    let br = sig.get(b"ByteRange").ok()?.as_array().ok()?;
    if br.len() != 4 {
        return None;
    }
    let start = br[2].as_i64().ok()?;
    let len = br[3].as_i64().ok()?;
    usize::try_from(start.checked_add(len)?).ok()
}

/// Whether the CMS carries an `id-aa-signatureTimeStampToken` unsigned attribute.
fn detect_signature_timestamp(cms_der: &[u8]) -> Result<bool, PadesError> {
    let ci = ContentInfo::from_der(cms_der)?;
    let sd: SignedData = ci.content.decode_as()?;
    let Some(signer) = sd.signer_infos.0.iter().next() else {
        return Ok(false);
    };
    let present = signer
        .unsigned_attrs
        .as_ref()
        .map(|attrs| {
            attrs
                .iter()
                .any(|a| a.oid == ID_AA_SIGNATURE_TIME_STAMP_TOKEN)
        })
        .unwrap_or(false);
    Ok(present)
}

/// Convert a ByteRange integer to `usize`, rejecting negatives.
fn usize_of(v: i64) -> Result<usize, PadesError> {
    usize::try_from(v).map_err(|_| PadesError::InvalidByteRange)
}
