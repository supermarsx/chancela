//! Structural + delegated validation of a signed PDF (SIG-24).
//!
//! Locate the `/Sig` dictionary, recompute the `/ByteRange` digest over the raw file bytes, and
//! hand the embedded CMS to `chancela_cades::validate_cades_b` for the cryptographic check. Trust
//! and qualified-status decisions belong to `chancela-tsl` / `chancela-signing`, not here.

use std::collections::BTreeSet;

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::certificate::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier};

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
        if let Some(base_catalog) = document_catalog(base)
            && catalog_change_is_dss_only(base_catalog, catalog)
        {
            benign.insert(root_id);
        }
    }

    // --- DocTimeStamp revision: every `/DocTimeStamp` dictionary and its `/Sig` form field ---
    for (id, obj) in &full.objects {
        if let Ok(dict) = obj.as_dict()
            && (dict
                .get_type()
                .map(|ty| ty == b"DocTimeStamp")
                .unwrap_or(false)
                || is_doc_timestamp_field(full, dict))
        {
            benign.insert(*id);
        }
    }
    // …and the AcroForm that lists those fields, only if it changed nothing but `/Fields`/`/SigFlags`.
    if let Ok(acroform_ref) = catalog
        .get(b"AcroForm")
        .and_then(lopdf::Object::as_reference)
        && let (Ok(full_acroform), Some(base_acroform)) = (
            full.get_object(acroform_ref)
                .and_then(lopdf::Object::as_dict),
            document_acroform(base),
        )
        && acroform_change_is_field_list_only(base_acroform, full_acroform)
    {
        benign.insert(acroform_ref);
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

// =====================================================================================
// Offline full-chain LTV verifier over embedded /DSS + /DocTimeStamp (wp26 E9, SIG-21).
//
// This is a **leaf-crate, no-network** check. It confirms the long-term-validation material a
// B-LT/B-LTA signature already carries is internally complete: it rebuilds the signer certificate
// chain from the certificates embedded in `/DSS /Certs` — **cryptographically verifying each CA
// link's signature** (RSA-PKCS1-SHA256 / ECDSA-P256-SHA256 only) — confirms every non-root link is
// backed by an embedded OCSP response or CRL, and checks the `/DocTimeStamp` renewal chain is
// contiguous. It does NOT fetch revocation data and does NOT anchor the chain to a trusted list —
// trust anchoring and live revocation stay with the online caller (`chancela-signing` +
// `chancela-tsl`). The signer's *own* signature is cryptographically verified, via
// [`validate_pdf_signature`], before any of this runs.
// =====================================================================================

/// DER OID content octets for `id-sha256` (2.16.840.1.101.3.4.2.1). OCSP `CertID` hashes computed
/// with any other algorithm (notably the RFC 6960 default SHA-1) are treated as "not matched" here,
/// because this leaf crate only links `sha2` and must not add a dependency to hash SHA-1.
const SHA256_OID_CONTENT: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// `sha256WithRSAEncryption` — the only RSA certificate-signature algorithm this verifier accepts.
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// `ecdsa-with-SHA256` — the only ECDSA certificate-signature algorithm this verifier accepts.
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2), for unprefixed RSA-PKCS1 verification.
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Honest scope statement carried in every [`LtvVerificationReport`]. This is a technical,
/// structural + revocation-completeness result over embedded material — **not** a trust decision,
/// qualified-status finding, or legal long-term-validation claim.
pub const LTV_OFFLINE_SCOPE_NOTE: &str = "Offline chain + revocation-completeness check over \
embedded PAdES LTV material only: the signer certificate chain is rebuilt from the embedded /DSS \
certificates (issuer/subject name + key-identifier linkage) and each CA link's signature is \
cryptographically verified (RSA-PKCS1-SHA256 / ECDSA-P256-SHA256 only), each non-root link is \
confirmed covered by an embedded OCSP response or CRL, and the /DocTimeStamp renewal chain is checked \
for contiguity. It does not fetch revocation data and does not anchor the chain to a trusted list; \
live revocation and trust anchoring remain the online caller's responsibility (chancela-signing + \
chancela-tsl). This reports embedded LTV completeness, not a qualified-status or legal \
long-term-validation conclusion.";

/// Why a rebuilt signer-chain link is not backed by embedded long-term-validation material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LtvUncoveredReason {
    /// No embedded `/DSS /Certs` certificate issued this one (by name + key-identifier linkage with
    /// a verifying signature), so the chain could not be extended to a self-issued root. The
    /// embedded material is structurally incomplete.
    IssuerNotEmbedded,
    /// A name/key-identifier-matching embedded issuer was found, but it does not cryptographically
    /// sign this certificate (RSA-PKCS1-SHA256 / ECDSA-P256-SHA256), or the certificate signature
    /// algorithm is unsupported. The chain does not verify at this link.
    IssuerSignatureInvalid,
    /// The issuer certificate is embedded and verifies, but no embedded OCSP response or CRL covers
    /// this link (matching CertID / issuer + non-revoked serial). The revocation material is
    /// incomplete.
    NoEmbeddedRevocation,
}

/// A signer-chain link whose offline long-term-validation coverage is incomplete.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LtvUncoveredLink {
    /// Position of the certificate in the rebuilt chain (`0` = signer leaf).
    pub index: usize,
    /// Subject distinguished name of the certificate (RFC 4514 string).
    pub subject: String,
    /// Lowercase hex of the certificate serial number.
    pub serial_hex: String,
    /// Why this link is not covered.
    pub reason: LtvUncoveredReason,
}

/// Offline long-term-validation completeness report for a B-LT/B-LTA signature (wp26 E9).
///
/// Produced by [`verify_ltv_offline`] using only the material embedded in the PDF. See
/// [`LTV_OFFLINE_SCOPE_NOTE`] (also carried in [`Self::scope_note`]) for the honest scope boundary:
/// this is structural + revocation completeness, not trust anchoring or a legal LTV claim.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LtvVerificationReport {
    /// Number of certificates in the chain rebuilt from the signer, inclusive (`1` when the signer
    /// is itself self-issued, i.e. there was no separate CA to embed).
    pub signer_chain_len: usize,
    /// Whether the rebuilt chain terminates in a self-issued (root) certificate that is present
    /// among the embedded `/DSS /Certs`, with every CA link's signature cryptographically verified.
    /// Offline this states internal consistency + coverage, **not** that the root is a *trusted*
    /// anchor — trust anchoring is the online caller's job.
    pub chain_terminates_in_embedded_root: bool,
    /// Whether every non-root link that has an embedded issuer is covered by an embedded OCSP/CRL.
    pub all_links_revocation_covered: bool,
    /// Links whose coverage is incomplete (missing issuer and/or missing revocation), signer-first.
    pub uncovered_links: Vec<LtvUncoveredLink>,
    /// Number of embedded `/DocTimeStamp` archive-timestamp revisions.
    pub doc_timestamp_count: usize,
    /// Whether the `/DocTimeStamp` renewal chain is contiguous: every archive timestamp's RFC 3161
    /// imprint validates over its `/ByteRange` (which, being a later incremental revision, covers the
    /// prior revision including its DSS), and each successive timestamp covers strictly more of the
    /// file than the previous one. Vacuously `false` when there is no archive timestamp.
    pub renewal_chain_contiguous: bool,
    /// Whether the signature is LTV-complete offline and still covers the rendered document: the
    /// signature coverage gate passed, the chain was rebuilt to an embedded root, and every link is
    /// revocation-covered (`coverage.covers_rendered_document() &&
    /// chain_terminates_in_embedded_root && uncovered_links empty`). This is **not** a trust or
    /// qualified-status verdict; see [`Self::scope_note`].
    pub verified_offline: bool,
    /// Honest scope statement (equal to [`LTV_OFFLINE_SCOPE_NOTE`]).
    pub scope_note: &'static str,
}

/// Verify — **offline, no network** — that a B-LT/B-LTA signature carries complete long-term
/// validation material: rebuild the signer chain from embedded `/DSS` certificates, confirm each
/// non-root link is covered by an embedded OCSP/CRL, and check the `/DocTimeStamp` renewal chain.
///
/// The signer's own CMS signature and `/ByteRange` coverage are verified first (via
/// [`validate_pdf_signature`]); the final positive verdict also requires that coverage to bind the
/// rendered document. This then walks only the material embedded in the PDF. It performs no trust
/// anchoring and no live fetching — see [`LtvVerificationReport`] and [`LTV_OFFLINE_SCOPE_NOTE`].
///
/// Returns `Err` for the same reasons as [`validate_pdf_signature`] (no signature, malformed
/// ByteRange/Contents, CMS failure) or if the embedded `/DSS` structure is malformed.
pub fn verify_ltv_offline(signed_pdf: &[u8]) -> Result<LtvVerificationReport, PadesError> {
    // 1. Locate + cryptographically verify the signer's own signature, and reuse its signer cert +
    //    DSS/DocTimeStamp reports. Any tampering or bad CMS fails here before we look at LTV material.
    let base = validate_pdf_signature(signed_pdf)?;
    let doc =
        lopdf::Document::load_mem(signed_pdf).map_err(|e| PadesError::PdfParse(e.to_string()))?;

    // 2. Collect the DER blobs embedded in /DSS /Certs, /OCSPs, /CRLs.
    let cert_ders = dss_stream_blobs(&doc, b"Certs")?;
    let ocsp_ders = dss_stream_blobs(&doc, b"OCSPs")?;
    let crl_ders = dss_stream_blobs(&doc, b"CRLs")?;

    let embedded: Vec<ChainCert> = cert_ders
        .iter()
        .filter_map(|d| ChainCert::parse(d))
        .collect();

    // 3. Rebuild the signer path from the embedded certs and record per-link revocation coverage.
    let mut chain_len = 0usize;
    let mut terminates = false;
    let mut uncovered: Vec<LtvUncoveredLink> = Vec::new();

    if let Some(signer) = ChainCert::parse(&base.cades.signer_cert_der) {
        let mut visited: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut current = signer;
        loop {
            chain_len += 1;
            let index = chain_len - 1;
            let node_key = (current.subject_der.clone(), current.serial.clone());
            let seen = visited.contains(&node_key);
            visited.push(node_key);

            if current.is_self_issued() {
                terminates = true;
                break;
            }
            if seen || chain_len > 32 {
                // Defensive cycle / runaway guard: stop without claiming a root was reached.
                uncovered.push(current.uncovered(index, LtvUncoveredReason::IssuerNotEmbedded));
                break;
            }

            // Candidate issuers by name + CA + key-identifier linkage; then require one whose public
            // key actually verifies this certificate's signature (RSA-SHA256 / P-256-ECDSA-SHA256).
            let name_candidates: Vec<&ChainCert> = embedded
                .iter()
                .filter(|cand| {
                    cand.subject_der == current.issuer_der
                        && cand.is_ca
                        && aki_ski_match(&current, cand)
                })
                .collect();
            let verified_issuer = name_candidates
                .iter()
                .copied()
                .find(|issuer| verify_child_signature(&current.cert, &issuer.cert));

            match verified_issuer {
                Some(issuer) => {
                    if !link_revocation_covered(&current, issuer, &ocsp_ders, &crl_ders) {
                        uncovered.push(
                            current.uncovered(index, LtvUncoveredReason::NoEmbeddedRevocation),
                        );
                    }
                    current = issuer.clone();
                }
                None if !name_candidates.is_empty() => {
                    // An issuer's name/key-id lined up but its key did not sign this cert.
                    uncovered
                        .push(current.uncovered(index, LtvUncoveredReason::IssuerSignatureInvalid));
                    break;
                }
                None => {
                    uncovered.push(current.uncovered(index, LtvUncoveredReason::IssuerNotEmbedded));
                    break;
                }
            }
        }
    }

    let all_links_revocation_covered = !uncovered
        .iter()
        .any(|u| u.reason == LtvUncoveredReason::NoEmbeddedRevocation);

    // 4. Verify the /DocTimeStamp renewal chain (B-LTA) from the archive-timestamp report.
    let doc_timestamp_count = base.doc_timestamps.count;
    let renewal_chain_contiguous = renewal_chain_contiguous(&base.doc_timestamps);

    // 5. Offline LTV completeness verdict: the verified CMS must also cover the rendered document,
    //    then the chain must rebuild to an embedded root with every link covered.
    let signature_covers_rendered_document = base.coverage.covers_rendered_document();
    let verified_offline =
        signature_covers_rendered_document && chain_len >= 1 && terminates && uncovered.is_empty();

    Ok(LtvVerificationReport {
        signer_chain_len: chain_len,
        chain_terminates_in_embedded_root: terminates,
        all_links_revocation_covered,
        uncovered_links: uncovered,
        doc_timestamp_count,
        renewal_chain_contiguous,
        verified_offline,
        scope_note: LTV_OFFLINE_SCOPE_NOTE,
    })
}

/// A parsed embedded certificate with the fields the offline chain rebuild + coverage checks need.
#[derive(Clone)]
struct ChainCert {
    cert: Certificate,
    /// DER of the subject `Name`.
    subject_der: Vec<u8>,
    /// DER of the issuer `Name`.
    issuer_der: Vec<u8>,
    /// Serial number bytes (canonical, sign-normalized on comparison).
    serial: Vec<u8>,
    /// Raw `subjectPublicKey` BIT STRING value (for OCSP `issuerKeyHash` matching).
    public_key: Vec<u8>,
    /// `subjectKeyIdentifier`, if present.
    ski: Option<Vec<u8>>,
    /// `authorityKeyIdentifier` keyIdentifier, if present.
    aki: Option<Vec<u8>>,
    /// Whether `basicConstraints` marks this a CA (required of any selected issuer).
    is_ca: bool,
}

impl ChainCert {
    fn parse(der: &[u8]) -> Option<Self> {
        let cert = Certificate::from_der(der).ok()?;
        let tbs = &cert.tbs_certificate;
        let subject_der = tbs.subject.to_der().ok()?;
        let issuer_der = tbs.issuer.to_der().ok()?;
        let serial = tbs.serial_number.as_bytes().to_vec();
        let public_key = tbs
            .subject_public_key_info
            .subject_public_key
            .as_bytes()?
            .to_vec();
        let ski = tbs
            .get::<SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .map(|(_, s)| s.0.as_bytes().to_vec());
        let aki = tbs
            .get::<AuthorityKeyIdentifier>()
            .ok()
            .flatten()
            .and_then(|(_, a)| a.key_identifier.map(|k| k.as_bytes().to_vec()));
        let is_ca = tbs
            .get::<BasicConstraints>()
            .ok()
            .flatten()
            .map(|(_, b)| b.ca)
            .unwrap_or(false);
        Some(ChainCert {
            cert,
            subject_der,
            issuer_der,
            serial,
            public_key,
            ski,
            aki,
            is_ca,
        })
    }

    fn is_self_issued(&self) -> bool {
        self.subject_der == self.issuer_der
    }

    fn uncovered(&self, index: usize, reason: LtvUncoveredReason) -> LtvUncoveredLink {
        LtvUncoveredLink {
            index,
            subject: self.cert.tbs_certificate.subject.to_string(),
            serial_hex: String::from_utf8(pdf::to_hex(&self.serial)).unwrap_or_default(),
            reason,
        }
    }
}

/// Whether a candidate issuer's subjectKeyIdentifier is consistent with the child's
/// authorityKeyIdentifier. Absent identifiers do not block the link (name match still applies).
fn aki_ski_match(child: &ChainCert, candidate: &ChainCert) -> bool {
    match (&child.aki, &candidate.ski) {
        (Some(aki), Some(ski)) => aki == ski,
        _ => true,
    }
}

/// Whether `issuer`'s public key cryptographically signs `child` (RSA-PKCS1-SHA256 or
/// ECDSA-P256-SHA256 only). Mirrors the conservative offline path check in `chancela-tsa/path.rs`:
/// the certificate's outer `signatureAlgorithm` must match the inner `TBSCertificate.signature`, and
/// any unsupported algorithm is rejected rather than guessed. No trust, validity, or revocation
/// decision is made here — only the signature bytes over the TBS.
fn verify_child_signature(child: &Certificate, issuer: &Certificate) -> bool {
    if child.signature_algorithm.oid != child.tbs_certificate.signature.oid {
        return false;
    }
    let Some(signature) = child.signature.as_bytes() else {
        return false;
    };
    let Ok(tbs_der) = child.tbs_certificate.to_der() else {
        return false;
    };
    if child.signature_algorithm.oid == OID_SHA256_WITH_RSA {
        verify_cert_rsa_sha256(issuer, signature, &tbs_der)
    } else if child.signature_algorithm.oid == OID_ECDSA_WITH_SHA256 {
        verify_cert_ecdsa_sha256(issuer, signature, &tbs_der)
    } else {
        false
    }
}

/// Verify an RSA-PKCS1-v1.5-SHA256 certificate signature against `issuer`'s public key.
fn verify_cert_rsa_sha256(issuer: &Certificate, signature: &[u8], message: &[u8]) -> bool {
    use der::referenced::OwnedToRef;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};

    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    let Ok(public_key) = RsaPublicKey::try_from(spki) else {
        return false;
    };
    let hash = Sha256::digest(message);
    let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
    digest_info.extend_from_slice(&hash);
    public_key
        .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .is_ok()
}

/// Verify an ECDSA-P256-SHA256 certificate signature against `issuer`'s public key.
fn verify_cert_ecdsa_sha256(issuer: &Certificate, signature: &[u8], message: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let Ok(spki_der) = issuer.tbs_certificate.subject_public_key_info.to_der() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_public_key_der(&spki_der) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(signature) else {
        return false;
    };
    verifying_key.verify(message, &sig).is_ok()
}

/// Whether `child` (issued by `issuer`) is covered by an embedded OCSP response or CRL.
fn link_revocation_covered(
    child: &ChainCert,
    issuer: &ChainCert,
    ocsp_ders: &[Vec<u8>],
    crl_ders: &[Vec<u8>],
) -> bool {
    ocsp_ders
        .iter()
        .any(|o| ocsp_covers_link(o, issuer, &child.serial))
        || crl_ders
            .iter()
            .any(|c| crl_covers_link(c, issuer, &child.serial))
}

/// Whether an embedded OCSP response carries a `SingleResponse` whose `CertID` matches this link:
/// SHA-256 `issuerNameHash`/`issuerKeyHash` over the issuer, and the child's serial number.
fn ocsp_covers_link(ocsp_der: &[u8], issuer: &ChainCert, child_serial: &[u8]) -> bool {
    let expected_name = Sha256::digest(&issuer.subject_der);
    let expected_key = Sha256::digest(&issuer.public_key);
    let want_serial = norm_serial(child_serial);
    for id in ocsp_certids(ocsp_der) {
        if id.alg_oid != SHA256_OID_CONTENT {
            continue;
        }
        if id.name_hash == expected_name.as_slice()
            && id.key_hash == expected_key.as_slice()
            && norm_serial(&id.serial) == want_serial
        {
            return true;
        }
    }
    false
}

/// Whether an embedded CRL is issued by this link's issuer and does not list the child's serial as
/// revoked (an affirmative "not revoked as of this CRL" for that issuer). No signature or validity
/// check is performed here — that is the online caller's job.
fn crl_covers_link(crl_der: &[u8], issuer: &ChainCert, child_serial: &[u8]) -> bool {
    let Ok(crl) = CertificateList::from_der(crl_der) else {
        return false;
    };
    let Ok(crl_issuer_der) = crl.tbs_cert_list.issuer.to_der() else {
        return false;
    };
    if crl_issuer_der != issuer.subject_der {
        return false;
    }
    let want_serial = norm_serial(child_serial);
    let listed = crl
        .tbs_cert_list
        .revoked_certificates
        .unwrap_or_default()
        .iter()
        .any(|r| norm_serial(r.serial_number.as_bytes()) == want_serial);
    !listed
}

/// One OCSP `CertID`, as raw bytes pulled out of a `SingleResponse`.
struct OcspCertId {
    alg_oid: Vec<u8>,
    name_hash: Vec<u8>,
    key_hash: Vec<u8>,
    serial: Vec<u8>,
}

/// Extract every `SingleResponse.certID` from an OCSP response's `BasicOCSPResponse`. Navigates the
/// DER structurally (RFC 6960) with a minimal walker so this leaf crate needs no `x509-ocsp` dep.
fn ocsp_certids(der: &[u8]) -> Vec<OcspCertId> {
    fn inner(der: &[u8]) -> Option<Vec<OcspCertId>> {
        // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, [0] EXPLICIT responseBytes }
        let (_, ocsp, _) = der_tlv(der)?;
        let response_bytes = der_children(ocsp)
            .into_iter()
            .find(|(tag, _)| *tag == 0xA0)
            .map(|(_, c)| c)?;
        // responseBytes [0] EXPLICIT wraps ResponseBytes ::= SEQUENCE { responseType, response OCTET }
        let (_, rb, _) = der_tlv(response_bytes)?;
        let basic_octet = der_children(rb)
            .into_iter()
            .find(|(tag, _)| *tag == 0x04)
            .map(|(_, c)| c)?;
        // OCTET STRING content = BasicOCSPResponse ::= SEQUENCE { tbsResponseData, .. }
        let (_, basic, _) = der_tlv(basic_octet)?;
        let (tbs_tag, tbs, _) = der_tlv(basic)?;
        if tbs_tag != 0x30 {
            return None;
        }
        // ResponseData: first universal SEQUENCE child is `responses` (version/responderID/producedAt
        // carry context or GeneralizedTime tags, so they do not collide).
        let responses = der_children(tbs)
            .into_iter()
            .find(|(tag, _)| *tag == 0x30)
            .map(|(_, c)| c)?;
        let mut ids = Vec::new();
        for (tag, single) in der_children(responses) {
            if tag != 0x30 {
                continue;
            }
            if let Some((0x30, certid)) = der_children(single).into_iter().next()
                && let Some(id) = parse_certid(certid)
            {
                ids.push(id);
            }
        }
        Some(ids)
    }
    inner(der).unwrap_or_default()
}

/// Parse the four fields of a `CertID ::= SEQUENCE { AlgorithmIdentifier, OCTET, OCTET, INTEGER }`.
fn parse_certid(content: &[u8]) -> Option<OcspCertId> {
    let children = der_children(content);
    let alg = children.iter().find(|(tag, _)| *tag == 0x30)?;
    let alg_oid = der_children(alg.1)
        .into_iter()
        .find(|(tag, _)| *tag == 0x06)
        .map(|(_, c)| c.to_vec())?;
    let octets: Vec<Vec<u8>> = children
        .iter()
        .filter(|(tag, _)| *tag == 0x04)
        .map(|(_, c)| c.to_vec())
        .collect();
    if octets.len() < 2 {
        return None;
    }
    let serial = children
        .iter()
        .find(|(tag, _)| *tag == 0x02)
        .map(|(_, c)| c.to_vec())?;
    Some(OcspCertId {
        alg_oid,
        name_hash: octets[0].clone(),
        key_hash: octets[1].clone(),
        serial,
    })
}

/// Parse one definite-length DER TLV at the start of `b`; returns `(tag, content, rest)`.
fn der_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if b.len() < 2 {
        return None;
    }
    let tag = b[0];
    let len_byte = b[1];
    let (content_start, len) = if len_byte < 0x80 {
        (2usize, len_byte as usize)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for &x in &b[2..2 + n] {
            len = (len << 8) | x as usize;
        }
        (2 + n, len)
    };
    let end = content_start.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some((tag, &b[content_start..end], &b[end..]))
}

/// Split a constructed value's content bytes into its `(tag, content)` TLV children.
fn der_children(mut content: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while !content.is_empty() {
        match der_tlv(content) {
            Some((tag, c, rest)) => {
                out.push((tag, c));
                content = rest;
            }
            None => break,
        }
    }
    out
}

/// Strip leading zero bytes so DER-INTEGER serials (which may carry a sign-padding `0x00`) compare
/// equal regardless of encoding. Serials are positive, so this is safe.
fn norm_serial(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < s.len() && s[i] == 0 {
        i += 1;
    }
    &s[i..]
}

/// Whether the `/DocTimeStamp` renewal chain is contiguous: at least one archive timestamp, every
/// imprint valid over its `/ByteRange`, and each successive timestamp covers strictly more of the
/// file (so a later timestamp covers the earlier revision — including its DSS).
fn renewal_chain_contiguous(dts: &DocTimeStampReport) -> bool {
    if dts.count == 0 || dts.validations.len() != dts.count {
        return false;
    }
    let mut prev_end = 0i64;
    for v in &dts.validations {
        if v.status != archive_timestamp::DocTimeStampSemanticStatus::Valid {
            return false;
        }
        let Some([_, _, s2, l2]) = v.byte_range else {
            return false;
        };
        let Some(end) = s2.checked_add(l2) else {
            return false;
        };
        if end <= prev_end {
            return false;
        }
        prev_end = end;
    }
    true
}

/// Collect the raw DER content of every stream referenced by `/DSS /<key>` (`Certs`/`OCSPs`/`CRLs`)
/// in the latest catalog. Mirrors the extraction in [`crate::dss`] but returns the bytes.
fn dss_stream_blobs(doc: &lopdf::Document, key: &[u8]) -> Result<Vec<Vec<u8>>, PadesError> {
    let Some(catalog) = document_catalog(doc) else {
        return Ok(Vec::new());
    };
    let Ok(dss_obj) = catalog.get(b"DSS") else {
        return Ok(Vec::new());
    };
    let (_, dss_obj) = doc
        .dereference(dss_obj)
        .map_err(|e| PadesError::MalformedStructure(format!("DSS reference is invalid: {e}")))?;
    let Ok(dss) = dss_obj.as_dict() else {
        return Ok(Vec::new());
    };
    let Ok(array_obj) = dss.get(key) else {
        return Ok(Vec::new());
    };
    let (_, array_obj) = doc.dereference(array_obj).map_err(|e| {
        PadesError::MalformedStructure(format!(
            "DSS /{} reference is invalid: {e}",
            String::from_utf8_lossy(key)
        ))
    })?;
    let Ok(array) = array_obj.as_array() else {
        return Ok(Vec::new());
    };
    let mut blobs = Vec::with_capacity(array.len());
    for item in array {
        let (_, item) = doc.dereference(item).map_err(|e| {
            PadesError::MalformedStructure(format!(
                "DSS /{} entry reference is invalid: {e}",
                String::from_utf8_lossy(key)
            ))
        })?;
        let stream = item.as_stream().map_err(|_| {
            PadesError::MalformedStructure(format!(
                "DSS /{} entry is not a stream",
                String::from_utf8_lossy(key)
            ))
        })?;
        blobs.push(stream.content.clone());
    }
    Ok(blobs)
}

#[cfg(test)]
mod ltv_tests {
    //! Inline offline full-chain LTV verifier tests (wp26 E9).
    //!
    //! These are self-contained (they cannot reach `crate::tests`' private helpers): they mint a
    //! real two-level chain (root CA -> CA-issued signer leaf), sign a PDF with the leaf, embed a
    //! complete `/DSS` (chain certs + OCSP/CRL per link), and drive [`verify_ltv_offline`]. OCSP/CRL
    //! material is minted to match the link so coverage is genuine, not fixture-shaped.

    use std::str::FromStr;
    use std::time::Duration as StdDuration;

    use der::asn1::{Any, BitString, ObjectIdentifier, OctetString};
    use der::oid::AssociatedOid;
    use der::{Decode, Encode};
    use rsa::rand_core::OsRng;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};
    use x509_cert::certificate::{TbsCertificate, Version};
    use x509_cert::crl::{CertificateList, TbsCertList};
    use x509_cert::ext::pkix::BasicConstraints;
    use x509_cert::ext::{Extension, Extensions};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};

    use chancela_cades::{
        RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest,
    };

    use super::{
        Certificate, LtvUncoveredReason, PdfSignatureCoverage, validate_pdf_signature,
        verify_ltv_offline,
    };
    use crate::dss::{DssEvidence, add_dss_revision};
    use crate::sign::{SignOptions, sign_pdf};
    use crate::{add_doc_timestamp_revision, inspect_doc_timestamps};

    const OID_SHA256_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const LEAF_SERIAL: u8 = 0x2a;

    fn fixed_time() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn rsa_sig_alg() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        }
    }

    fn sign_rsa_digest_info(key: &RsaPrivateKey, digest: &[u8; 32]) -> Vec<u8> {
        let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
        digest_info.extend_from_slice(digest);
        key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
            .expect("rsa sign")
    }

    fn rsa_key() -> (RsaPrivateKey, SubjectPublicKeyInfoOwned) {
        let key = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let spki = SubjectPublicKeyInfoOwned::from_key(RsaPublicKey::from(&key)).expect("spki");
        (key, spki)
    }

    fn basic_constraints_ca() -> Extensions {
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        vec![Extension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: OctetString::new(bc.to_der().expect("bc der")).expect("octet"),
        }]
    }

    fn make_cert(
        subject_cn: &str,
        issuer_cn: &str,
        serial: u8,
        spki: SubjectPublicKeyInfoOwned,
        extensions: Option<Extensions>,
        signer_key: &RsaPrivateKey,
    ) -> Vec<u8> {
        let sig_alg = rsa_sig_alg();
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[serial]).expect("serial"),
            signature: sig_alg.clone(),
            issuer: Name::from_str(&format!("CN={issuer_cn}")).expect("issuer"),
            validity: Validity::from_now(StdDuration::from_secs(3650 * 24 * 3600))
                .expect("validity"),
            subject: Name::from_str(&format!("CN={subject_cn}")).expect("subject"),
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions,
        };
        let tbs_der = tbs.to_der().expect("tbs der");
        let signature = sign_rsa_digest_info(signer_key, &sha256(&tbs_der));
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&signature).expect("bitstring"),
        };
        cert.to_der().expect("cert der")
    }

    /// Mint (root CA cert DER, leaf cert DER, leaf private key). The leaf is issued by the CA.
    fn mint_chain() -> (Vec<u8>, Vec<u8>, RsaPrivateKey) {
        let (ca_key, ca_spki) = rsa_key();
        let ca_der = make_cert(
            "Encosto CA Root",
            "Encosto CA Root",
            0x01,
            ca_spki,
            Some(basic_constraints_ca()),
            &ca_key,
        );
        let (leaf_key, leaf_spki) = rsa_key();
        let leaf_der = make_cert(
            "Amelia Marques Signer",
            "Encosto CA Root",
            LEAF_SERIAL,
            leaf_spki,
            None,
            &ca_key,
        );
        (ca_der, leaf_der, leaf_key)
    }

    fn base_pdf() -> Vec<u8> {
        let objects: [(u32, &str); 3] = [
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
        ];
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
        let mut offsets = Vec::new();
        for (id, body) in &objects {
            offsets.push((*id, buf.len()));
            buf.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
        }
        let xref_off = buf.len();
        buf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f\r\n");
        for id in 1..=3u32 {
            let off = offsets.iter().find(|(i, _)| *i == id).unwrap().1;
            buf.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
        }
        buf.extend_from_slice(b"trailer\n<< /Size 4 /Root 1 0 R >>\n");
        buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        buf
    }

    fn append_object_override(pdf: &[u8], obj_id: u32, new_body: &str) -> Vec<u8> {
        let doc = lopdf::Document::load_mem(pdf).expect("parse PDF");
        let root = doc
            .trailer
            .get(b"Root")
            .and_then(lopdf::Object::as_reference)
            .expect("root");
        let prev_startxref = crate::pdf::last_startxref(pdf).expect("startxref");
        let mut out = pdf.to_vec();
        let obj_offset = out.len() + 1;
        out.extend_from_slice(b"\n");
        out.extend_from_slice(format!("{obj_id} 0 obj\n{new_body}\nendobj\n").as_bytes());
        let xref_offset = out.len();
        out.extend_from_slice(
            format!(
                "xref\n{obj_id} 1\n{obj_offset:010} 00000 n\r\ntrailer\n<< /Size {} /Root {} 0 R /Prev {prev_startxref} >>\nstartxref\n{xref_offset}\n%%EOF\n",
                doc.max_id + 1,
                root.0
            )
            .as_bytes(),
        );
        out
    }

    fn sign_pdf_with_leaf(pdf: &[u8], leaf_der: &[u8], leaf_key: &RsaPrivateKey) -> Vec<u8> {
        let signing_time = fixed_time();
        sign_pdf(pdf, &SignOptions::default(), |digest| {
            let attrs = signed_attributes_digest(digest, leaf_der, signing_time)?;
            let raw = RawSignature::new(
                SignatureAlgorithm::RsaPkcs1Sha256,
                sign_rsa_digest_info(leaf_key, &attrs),
                leaf_der.to_vec(),
                vec![],
            );
            assemble_cades_b(&raw, digest, signing_time)
        })
        .expect("sign_pdf")
    }

    /// Minimal DER TLV (definite length).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let len = content.len();
        if len < 0x80 {
            v.push(len as u8);
        } else {
            let bytes = len.to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap();
            v.push(0x80 | (bytes.len() - first) as u8);
            v.extend_from_slice(&bytes[first..]);
        }
        v.extend_from_slice(content);
        v
    }

    /// Build a minimal RFC 6960 OCSP response with one SingleResponse whose SHA-256 CertID names
    /// `issuer_der` and `serial`. Only the fields the offline verifier navigates are populated.
    fn make_ocsp(issuer_der: &[u8], serial: &[u8]) -> Vec<u8> {
        let issuer = Certificate::from_der(issuer_der).expect("issuer der");
        let name_der = issuer.tbs_certificate.subject.to_der().expect("name der");
        let key = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .expect("pubkey")
            .to_vec();
        let sha256_oid = [0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let alg = tlv(0x30, &[tlv(0x06, &sha256_oid), tlv(0x05, &[])].concat());
        let cert_id = tlv(
            0x30,
            &[
                alg,
                tlv(0x04, &Sha256::digest(&name_der)),
                tlv(0x04, &Sha256::digest(&key)),
                tlv(0x02, serial),
            ]
            .concat(),
        );
        let single = tlv(0x30, &cert_id);
        let responses = tlv(0x30, &single);
        let response_data = tlv(0x30, &responses);
        let basic = tlv(0x30, &response_data);
        let ocsp_basic_oid = [0x2bu8, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
        let response_bytes = tlv(
            0x30,
            &[tlv(0x06, &ocsp_basic_oid), tlv(0x04, &basic)].concat(),
        );
        tlv(
            0x30,
            &[tlv(0x0A, &[0x00]), tlv(0xA0, &response_bytes)].concat(),
        )
    }

    /// Build a CRL issued by `issuer_der`'s subject with an empty revoked list.
    fn make_crl(issuer_der: &[u8], signer_key: &RsaPrivateKey) -> Vec<u8> {
        let issuer = Certificate::from_der(issuer_der).expect("issuer der");
        let sig_alg = rsa_sig_alg();
        let tbs = TbsCertList {
            version: Version::V2,
            signature: sig_alg.clone(),
            issuer: issuer.tbs_certificate.subject.clone(),
            this_update: Time::try_from(std::time::SystemTime::now()).expect("time"),
            next_update: None,
            revoked_certificates: None,
            crl_extensions: None,
        };
        let tbs_der = tbs.to_der().expect("tbs crl der");
        let signature = sign_rsa_digest_info(signer_key, &sha256(&tbs_der));
        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&signature).expect("bitstring"),
        };
        crl.to_der().expect("crl der")
    }

    fn fixture_timestamp_token() -> Vec<u8> {
        let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
        let req = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
            .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
            .without_certificate();
        tsa.stamp(&req).expect("fixture token").token_der
    }

    fn doc_timestamp_token_for(pdf: &[u8]) -> Vec<u8> {
        let placeholder =
            add_doc_timestamp_revision(pdf, &fixture_timestamp_token()).expect("placeholder DTS");
        let report = inspect_doc_timestamps(&placeholder).expect("inspect placeholder");
        let digest = report.validations[0]
            .document_digest
            .expect("DocTimeStamp digest");
        let mut token = fixture_timestamp_token();
        let width = chancela_tsa::mock::FIXTURE_DIGEST.len();
        let pos = token
            .windows(width)
            .position(|w| w == chancela_tsa::mock::FIXTURE_DIGEST)
            .expect("fixture imprint");
        token[pos..pos + width].copy_from_slice(&digest);
        token
    }

    #[test]
    fn complete_embedded_dss_verifies_offline_via_ocsp() {
        let (ca_der, leaf_der, leaf_key) = mint_chain();
        let signed = sign_pdf_with_leaf(&base_pdf(), &leaf_der, &leaf_key);
        let evidence = DssEvidence {
            certificates: vec![leaf_der.clone(), ca_der.clone()],
            ocsp_responses: vec![make_ocsp(&ca_der, &[LEAF_SERIAL])],
            crls: vec![],
        };
        let with_dss = add_dss_revision(&signed, &evidence).expect("DSS append");

        let report = verify_ltv_offline(&with_dss).expect("verify LTV");
        assert_eq!(report.signer_chain_len, 2, "signer -> CA root");
        assert!(report.chain_terminates_in_embedded_root);
        assert!(report.all_links_revocation_covered);
        assert!(
            report.uncovered_links.is_empty(),
            "{:?}",
            report.uncovered_links
        );
        assert!(report.verified_offline);
        assert!(!report.scope_note.to_lowercase().contains("valor probat"));
    }

    #[test]
    fn complete_embedded_dss_verifies_offline_via_crl() {
        let (ca_der, leaf_der, leaf_key) = mint_chain();
        let signed = sign_pdf_with_leaf(&base_pdf(), &leaf_der, &leaf_key);
        let evidence = DssEvidence {
            certificates: vec![leaf_der.clone(), ca_der.clone()],
            ocsp_responses: vec![],
            crls: vec![make_crl(&ca_der, &leaf_key)],
        };
        let with_dss = add_dss_revision(&signed, &evidence).expect("DSS append");

        let report = verify_ltv_offline(&with_dss).expect("verify LTV");
        assert!(report.all_links_revocation_covered);
        assert!(report.verified_offline);
        assert!(report.uncovered_links.is_empty());
    }

    #[test]
    fn altered_rendered_document_is_not_verified_offline() {
        let (ca_der, leaf_der, leaf_key) = mint_chain();
        let signed = sign_pdf_with_leaf(&base_pdf(), &leaf_der, &leaf_key);
        let evidence = DssEvidence {
            certificates: vec![leaf_der.clone(), ca_der.clone()],
            ocsp_responses: vec![make_ocsp(&ca_der, &[LEAF_SERIAL])],
            crls: vec![],
        };
        let with_dss = add_dss_revision(&signed, &evidence).expect("DSS append");
        let altered = append_object_override(
            &with_dss,
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Resources << >> >>",
        );

        let base_report = validate_pdf_signature(&altered).expect("validate altered PDF");
        assert_eq!(
            base_report.coverage,
            PdfSignatureCoverage::AlteredAfterSigning
        );
        assert!(!base_report.coverage.covers_rendered_document());

        let report = verify_ltv_offline(&altered).expect("verify LTV");
        assert_eq!(report.signer_chain_len, 2);
        assert!(report.chain_terminates_in_embedded_root);
        assert!(report.uncovered_links.is_empty());
        assert!(report.all_links_revocation_covered);
        assert!(
            !report.verified_offline,
            "altered rendered-document coverage must block a positive offline LTV verdict"
        );
    }

    #[test]
    fn missing_link_revocation_is_reported_uncovered() {
        let (ca_der, leaf_der, leaf_key) = mint_chain();
        let signed = sign_pdf_with_leaf(&base_pdf(), &leaf_der, &leaf_key);
        // OCSP names a different serial, so it does not cover the signer leaf.
        let evidence = DssEvidence {
            certificates: vec![leaf_der.clone(), ca_der.clone()],
            ocsp_responses: vec![make_ocsp(&ca_der, &[0x2b])],
            crls: vec![],
        };
        let with_dss = add_dss_revision(&signed, &evidence).expect("DSS append");

        let report = verify_ltv_offline(&with_dss).expect("verify LTV");
        assert_eq!(report.signer_chain_len, 2);
        assert!(
            report.chain_terminates_in_embedded_root,
            "CA root still reached"
        );
        assert!(!report.all_links_revocation_covered);
        assert_eq!(report.uncovered_links.len(), 1);
        assert_eq!(report.uncovered_links[0].index, 0, "signer leaf uncovered");
        assert_eq!(
            report.uncovered_links[0].reason,
            LtvUncoveredReason::NoEmbeddedRevocation
        );
        assert!(!report.verified_offline);
    }

    #[test]
    fn tampered_intermediate_with_matching_name_is_rejected() {
        let (_real_ca, leaf_der, leaf_key) = mint_chain();
        // A substituted "CA": same subject DN and basicConstraints, but an unrelated key — so it
        // does NOT cryptographically sign the leaf even though the names line up.
        let (fake_key, fake_spki) = rsa_key();
        let fake_ca = make_cert(
            "Encosto CA Root",
            "Encosto CA Root",
            0x01,
            fake_spki,
            Some(basic_constraints_ca()),
            &fake_key,
        );
        let signed = sign_pdf_with_leaf(&base_pdf(), &leaf_der, &leaf_key);
        let evidence = DssEvidence {
            certificates: vec![leaf_der.clone(), fake_ca],
            ocsp_responses: vec![make_ocsp(&leaf_der, &[LEAF_SERIAL])],
            crls: vec![],
        };
        let with_dss = add_dss_revision(&signed, &evidence).expect("DSS append");

        let report = verify_ltv_offline(&with_dss).expect("verify LTV");
        assert!(!report.verified_offline, "wrong-key issuer must not verify");
        assert!(!report.chain_terminates_in_embedded_root);
        assert_eq!(report.uncovered_links.len(), 1);
        assert_eq!(report.uncovered_links[0].index, 0, "signer leaf link");
        assert_eq!(
            report.uncovered_links[0].reason,
            LtvUncoveredReason::IssuerSignatureInvalid
        );
    }

    #[test]
    fn blta_doc_timestamp_renewal_chain_is_contiguous() {
        let (ca_der, leaf_der, leaf_key) = mint_chain();
        let signed = sign_pdf_with_leaf(&base_pdf(), &leaf_der, &leaf_key);
        let evidence = DssEvidence {
            certificates: vec![leaf_der.clone(), ca_der.clone()],
            ocsp_responses: vec![make_ocsp(&ca_der, &[LEAF_SERIAL])],
            crls: vec![],
        };
        let with_dss = add_dss_revision(&signed, &evidence).expect("DSS append");
        let token = doc_timestamp_token_for(&with_dss);
        let with_dts = add_doc_timestamp_revision(&with_dss, &token).expect("DTS append");

        let report = verify_ltv_offline(&with_dts).expect("verify LTV");
        assert!(report.doc_timestamp_count >= 1);
        assert!(report.renewal_chain_contiguous);
        // The signer chain + revocation coverage still hold after the archive timestamp.
        assert!(report.verified_offline);
    }

    #[test]
    fn no_dss_is_not_verified_offline() {
        let (_ca_der, leaf_der, leaf_key) = mint_chain();
        let signed = sign_pdf_with_leaf(&base_pdf(), &leaf_der, &leaf_key);
        let report = verify_ltv_offline(&signed).expect("verify LTV");
        // The signer leaf is CA-issued but no issuer/revocation is embedded: incomplete offline.
        assert!(!report.verified_offline);
        assert!(!report.chain_terminates_in_embedded_root);
        assert_eq!(report.doc_timestamp_count, 0);
        assert!(!report.renewal_chain_contiguous);
    }
}
