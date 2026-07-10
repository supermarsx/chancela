//! Structural + delegated validation of a signed PDF (SIG-24).
//!
//! Locate the `/Sig` dictionary, recompute the `/ByteRange` digest over the raw file bytes, and
//! hand the embedded CMS to `chancela_cades::validate_cades_b` for the cryptographic check. Trust
//! and qualified-status decisions belong to `chancela-tsl` / `chancela-signing`, not here.

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
    /// Whether the ByteRange starts at 0 and extends to the end of the file (only the `/Contents`
    /// value is excluded) — the well-formed PAdES shape.
    pub covers_whole_file_except_contents: bool,
    /// Whether the ByteRange starts at 0 and extends to the end of the signed revision. This
    /// remains true when a later incremental update appends caller-supplied DSS evidence.
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
    let covers_signed_revision_except_contents = s1 == 0 && s1 + l1 <= s2;
    let covers_whole_file_except_contents =
        covers_signed_revision_except_contents && signed_revision_len == total;
    let has_later_incremental_updates = signed_revision_len < total;

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
