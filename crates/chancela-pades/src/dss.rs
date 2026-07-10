//! Local, caller-supplied PAdES DSS/VRI incremental updates.
//!
//! This module deliberately does not fetch OCSP/CRL material, validate revocation freshness, or
//! claim legal B-LT sufficiency. It only embeds and reports caller-supplied DER evidence in a
//! deterministic `/DSS` revision so higher layers can preserve and describe the bytes.

use sha2::{Digest, Sha256};

use crate::error::PadesError;
use crate::pdf;

type StreamRef = (u32, Vec<u8>);
type MergeRefs = (Vec<u32>, Vec<StreamRef>);

/// Caller-supplied validation material to embed in a PDF DSS revision.
///
/// Each entry must be a complete DER object. At least one OCSP response or CRL is required; signer
/// and issuer certificates are useful context but do not count as revocation evidence by
/// themselves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DssEvidence {
    /// DER-encoded certificates to place in `/DSS /Certs` and the matching `/VRI /Cert` array.
    pub certificates: Vec<Vec<u8>>,
    /// DER-encoded OCSP responses to place in `/DSS /OCSPs` and the matching `/VRI /OCSP` array.
    pub ocsp_responses: Vec<Vec<u8>>,
    /// DER-encoded CRLs to place in `/DSS /CRLs` and the matching `/VRI /CRL` array.
    pub crls: Vec<Vec<u8>>,
}

impl DssEvidence {
    /// Whether the evidence contains at least one revocation blob (OCSP or CRL).
    pub fn has_revocation_evidence(&self) -> bool {
        !self.ocsp_responses.is_empty() || !self.crls.is_empty()
    }
}

/// Technical report for embedded DSS/VRI evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DssReport {
    /// Whether the latest PDF catalog contains a `/DSS` dictionary.
    pub present: bool,
    /// Number of entries in the `/DSS /VRI` dictionary.
    pub vri_count: usize,
    /// `/DSS /VRI` dictionary keys, in PDF dictionary order.
    pub vri_keys: Vec<Vec<u8>>,
    /// Number of `/DSS /VRI` entries carrying `/TU` freshness metadata.
    pub vri_tu_count: usize,
    /// `/DSS /VRI` dictionary keys whose entries carry `/TU` freshness metadata.
    pub vri_tu_keys: Vec<Vec<u8>>,
    /// SHA-256 hashes of `/DSS /Certs` stream contents, in array order.
    pub certificate_hashes: Vec<[u8; 32]>,
    /// SHA-256 hashes of `/DSS /OCSPs` stream contents, in array order.
    pub ocsp_hashes: Vec<[u8; 32]>,
    /// SHA-256 hashes of `/DSS /CRLs` stream contents, in array order.
    pub crl_hashes: Vec<[u8; 32]>,
}

impl DssReport {
    /// Number of certificate blobs in `/DSS /Certs`.
    pub fn certificate_count(&self) -> usize {
        self.certificate_hashes.len()
    }

    /// Number of OCSP response blobs in `/DSS /OCSPs`.
    pub fn ocsp_count(&self) -> usize {
        self.ocsp_hashes.len()
    }

    /// Number of CRL blobs in `/DSS /CRLs`.
    pub fn crl_count(&self) -> usize {
        self.crl_hashes.len()
    }

    /// Whether the DSS report contains revocation material.
    pub fn has_revocation_evidence(&self) -> bool {
        self.ocsp_count() > 0 || self.crl_count() > 0
    }

    /// Whether any VRI entry carries `/TU` freshness metadata.
    pub fn has_vri_tu(&self) -> bool {
        self.vri_tu_count > 0
    }

    /// Whether the VRI entry for `vri_key` carries `/TU` freshness metadata.
    pub fn has_vri_tu_for_key(&self, vri_key: &[u8]) -> bool {
        self.vri_tu_keys.iter().any(|key| key.as_slice() == vri_key)
    }
}

/// Append a deterministic `/DSS` incremental update to a signed PDF.
///
/// Existing DSS dictionaries are merged deterministically: existing stream references are
/// preserved, new evidence is deduplicated by SHA-256 of the stream content, and the target VRI is
/// keyed by the lowercase SHA-256 hex digest of the selected signature's embedded CMS `/Contents`
/// DER.
pub fn add_dss_revision(signed_pdf: &[u8], evidence: &DssEvidence) -> Result<Vec<u8>, PadesError> {
    add_dss_revision_inner(signed_pdf, evidence, None)
}

/// Append a deterministic `/DSS` incremental update and include validation freshness metadata.
///
/// `validation_time` is written as the target VRI dictionary's `/TU` string. This records caller
/// metadata only; it does not fetch, validate, or claim long-term profile sufficiency.
pub fn add_dss_revision_with_validation_time(
    signed_pdf: &[u8],
    evidence: &DssEvidence,
    validation_time: &str,
) -> Result<Vec<u8>, PadesError> {
    add_dss_revision_inner(signed_pdf, evidence, Some(validation_time))
}

fn add_dss_revision_inner(
    signed_pdf: &[u8],
    evidence: &DssEvidence,
    validation_time: Option<&str>,
) -> Result<Vec<u8>, PadesError> {
    validate_evidence(evidence)?;

    let doc =
        lopdf::Document::load_mem(signed_pdf).map_err(|e| PadesError::PdfParse(e.to_string()))?;
    let prev_startxref = pdf::last_startxref(signed_pdf).ok_or(PadesError::MissingStartxref)?;
    if signed_pdf.get(prev_startxref..prev_startxref + 4) != Some(b"xref") {
        return Err(PadesError::MalformedStructure(
            "input PDF uses cross-reference streams; a classic xref table is required".into(),
        ));
    }

    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .map_err(|_| PadesError::MalformedStructure("trailer has no /Root reference".into()))?;
    let mut catalog = doc
        .get_object(root_id)
        .and_then(lopdf::Object::as_dict)
        .map_err(|_| PadesError::MalformedStructure("catalog object missing".into()))?
        .clone();

    let signature_der = target_signature_contents_der(&doc)?;
    let vri_key = pdf::to_hex(&Sha256::digest(&signature_der));

    let mut next_id = doc.max_id + 1;
    let dss_id = next_id;
    next_id += 1;
    let vri_id = next_id;
    next_id += 1;

    let existing = existing_dss_parts(&doc, &catalog)?;
    let (cert_ids, new_certs) = merge_evidence_refs(
        &doc,
        existing.cert_refs,
        &evidence.certificates,
        &mut next_id,
    )?;
    let (ocsp_ids, new_ocsps) = merge_evidence_refs(
        &doc,
        existing.ocsp_refs,
        &evidence.ocsp_responses,
        &mut next_id,
    )?;
    let (crl_ids, new_crls) =
        merge_evidence_refs(&doc, existing.crl_refs, &evidence.crls, &mut next_id)?;
    let max_new_id = next_id - 1;

    catalog.set("DSS", lopdf::Object::Reference((dss_id, 0)));
    let catalog_body = serialize_dict(&catalog)?;

    let dss_body = dss_dict_body(
        existing.vri,
        &vri_key,
        vri_id,
        &cert_ids,
        &ocsp_ids,
        &crl_ids,
    )?;
    let vri_body = vri_dict_body(&cert_ids, &ocsp_ids, &crl_ids, validation_time)?;

    let mut objects: Vec<(u32, Vec<u8>)> = vec![
        (root_id.0, catalog_body),
        (dss_id, dss_body),
        (vri_id, vri_body),
    ];
    objects.extend(
        new_certs
            .into_iter()
            .map(|(id, bytes)| (id, stream_body(&bytes))),
    );
    objects.extend(
        new_ocsps
            .into_iter()
            .map(|(id, bytes)| (id, stream_body(&bytes))),
    );
    objects.extend(
        new_crls
            .into_iter()
            .map(|(id, bytes)| (id, stream_body(&bytes))),
    );

    let section = incremental_section(
        signed_pdf.len(),
        prev_startxref,
        root_id.0,
        max_new_id,
        objects,
    );
    let mut out = signed_pdf.to_vec();
    out.extend_from_slice(&section);
    Ok(out)
}

/// Inspect the latest catalog's DSS dictionary and hash the embedded evidence streams.
pub fn inspect_dss(pdf_bytes: &[u8]) -> Result<DssReport, PadesError> {
    let doc =
        lopdf::Document::load_mem(pdf_bytes).map_err(|e| PadesError::PdfParse(e.to_string()))?;
    inspect_dss_document(&doc)
}

pub(crate) fn inspect_dss_document(doc: &lopdf::Document) -> Result<DssReport, PadesError> {
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .map_err(|_| PadesError::MalformedStructure("trailer has no /Root reference".into()))?;
    let catalog = doc
        .get_object(root_id)
        .and_then(lopdf::Object::as_dict)
        .map_err(|_| PadesError::MalformedStructure("catalog object missing".into()))?;
    let Ok(dss_obj) = catalog.get(b"DSS") else {
        return Ok(DssReport::default());
    };
    let (_, dss_obj) = doc
        .dereference(dss_obj)
        .map_err(|e| PadesError::MalformedStructure(format!("DSS reference is invalid: {e}")))?;
    let dss = dss_obj
        .as_dict()
        .map_err(|_| PadesError::MalformedStructure("DSS object is not a dictionary".into()))?;

    let (vri_count, vri_keys, vri_tu_keys) = match dss.get(b"VRI").ok() {
        Some(vri_obj) => {
            let (_, vri_obj) = doc.dereference(vri_obj).map_err(|e| {
                PadesError::MalformedStructure(format!("DSS /VRI reference is invalid: {e}"))
            })?;
            let vri = vri_obj.as_dict().map_err(|_| {
                PadesError::MalformedStructure("DSS /VRI is not a dictionary".into())
            })?;
            let mut vri_tu_keys = Vec::new();
            for (key, item) in vri.iter() {
                let (_, item) = doc.dereference(item).map_err(|e| {
                    PadesError::MalformedStructure(format!(
                        "DSS /VRI entry reference is invalid: {e}"
                    ))
                })?;
                if item.as_dict().map(|d| d.has(b"TU")).unwrap_or(false) {
                    vri_tu_keys.push(key.clone());
                }
            }
            (
                vri.len(),
                vri.iter().map(|(key, _)| key.clone()).collect(),
                vri_tu_keys,
            )
        }
        None => (0, Vec::new(), Vec::new()),
    };
    let vri_tu_count = vri_tu_keys.len();

    Ok(DssReport {
        present: true,
        vri_count,
        vri_keys,
        vri_tu_count,
        vri_tu_keys,
        certificate_hashes: stream_hashes(doc, dss, b"Certs")?,
        ocsp_hashes: stream_hashes(doc, dss, b"OCSPs")?,
        crl_hashes: stream_hashes(doc, dss, b"CRLs")?,
    })
}

fn validate_evidence(evidence: &DssEvidence) -> Result<(), PadesError> {
    if !evidence.has_revocation_evidence() {
        return Err(PadesError::DssEvidenceEmpty);
    }
    for (kind, blobs) in [
        ("certificate", &evidence.certificates),
        ("OCSP response", &evidence.ocsp_responses),
        ("CRL", &evidence.crls),
    ] {
        for (index, blob) in blobs.iter().enumerate() {
            validate_der_blob(kind, index, blob)?;
        }
    }
    Ok(())
}

fn validate_der_blob(kind: &'static str, index: usize, blob: &[u8]) -> Result<(), PadesError> {
    if blob.is_empty() || pdf::der_total_len(blob) != Some(blob.len()) {
        return Err(PadesError::InvalidDssEvidence { kind, index });
    }
    Ok(())
}

fn target_signature_contents_der(doc: &lopdf::Document) -> Result<Vec<u8>, PadesError> {
    let sig = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .filter(|d| d.get_type().map(|t| t == b"Sig").unwrap_or(false))
        .max_by_key(|d| signed_revision_len(d).unwrap_or(0))
        .ok_or(PadesError::NoSignature)?;
    let contents = sig
        .get(b"Contents")
        .and_then(lopdf::Object::as_str)
        .map_err(|_| PadesError::InvalidContents)?;
    let len = pdf::der_total_len(contents).ok_or(PadesError::InvalidContents)?;
    if len > contents.len() {
        return Err(PadesError::InvalidContents);
    }
    Ok(contents[..len].to_vec())
}

fn signed_revision_len(sig: &lopdf::Dictionary) -> Option<i64> {
    let br = sig.get(b"ByteRange").ok()?.as_array().ok()?;
    if br.len() != 4 {
        return None;
    }
    let start = br[2].as_i64().ok()?;
    let len = br[3].as_i64().ok()?;
    start.checked_add(len)
}

fn allocate_ids(next_id: &mut u32, count: usize) -> Vec<u32> {
    let start = *next_id;
    *next_id += u32::try_from(count).expect("PDF object count fits in u32");
    (start..*next_id).collect()
}

fn serialize_dict(dict: &lopdf::Dictionary) -> Result<Vec<u8>, PadesError> {
    let mut out = Vec::new();
    pdf::write_dict(dict, &mut out).map_err(|m| PadesError::MalformedStructure(m.into()))?;
    Ok(out)
}

fn dss_dict_body(
    existing_vri: lopdf::Dictionary,
    vri_key: &[u8],
    vri_id: u32,
    cert_ids: &[u32],
    ocsp_ids: &[u32],
    crl_ids: &[u32],
) -> Result<Vec<u8>, PadesError> {
    let mut vri = existing_vri;
    vri.set(vri_key.to_vec(), lopdf::Object::Reference((vri_id, 0)));

    let mut dss = lopdf::Dictionary::new();
    dss.set("Type", lopdf::Object::Name(b"DSS".to_vec()));
    dss.set("VRI", lopdf::Object::Dictionary(vri));
    if !cert_ids.is_empty() {
        dss.set("Certs", reference_array(cert_ids));
    }
    if !ocsp_ids.is_empty() {
        dss.set("OCSPs", reference_array(ocsp_ids));
    }
    if !crl_ids.is_empty() {
        dss.set("CRLs", reference_array(crl_ids));
    }
    serialize_dict(&dss)
}

fn vri_dict_body(
    cert_ids: &[u32],
    ocsp_ids: &[u32],
    crl_ids: &[u32],
    validation_time: Option<&str>,
) -> Result<Vec<u8>, PadesError> {
    let mut vri = lopdf::Dictionary::new();
    if !cert_ids.is_empty() {
        vri.set("Cert", reference_array(cert_ids));
    }
    if !ocsp_ids.is_empty() {
        vri.set("OCSP", reference_array(ocsp_ids));
    }
    if !crl_ids.is_empty() {
        vri.set("CRL", reference_array(crl_ids));
    }
    if let Some(validation_time) = validation_time {
        vri.set(
            "TU",
            lopdf::Object::String(
                validation_time.as_bytes().to_vec(),
                lopdf::StringFormat::Literal,
            ),
        );
    }
    serialize_dict(&vri)
}

#[derive(Default)]
struct ExistingDssParts {
    vri: lopdf::Dictionary,
    cert_refs: Vec<StreamRef>,
    ocsp_refs: Vec<StreamRef>,
    crl_refs: Vec<StreamRef>,
}

fn existing_dss_parts(
    doc: &lopdf::Document,
    catalog: &lopdf::Dictionary,
) -> Result<ExistingDssParts, PadesError> {
    let Some(dss_obj) = catalog.get(b"DSS").ok() else {
        return Ok(ExistingDssParts::default());
    };
    let (_, dss_obj) = doc
        .dereference(dss_obj)
        .map_err(|e| PadesError::MalformedStructure(format!("DSS reference is invalid: {e}")))?;
    let dss = dss_obj
        .as_dict()
        .map_err(|_| PadesError::MalformedStructure("DSS object is not a dictionary".into()))?;
    let vri = match dss.get(b"VRI").ok() {
        Some(vri_obj) => {
            let (_, vri_obj) = doc.dereference(vri_obj).map_err(|e| {
                PadesError::MalformedStructure(format!("DSS /VRI reference is invalid: {e}"))
            })?;
            vri_obj
                .as_dict()
                .map_err(|_| PadesError::MalformedStructure("DSS /VRI is not a dictionary".into()))?
                .clone()
        }
        None => lopdf::Dictionary::new(),
    };
    Ok(ExistingDssParts {
        vri,
        cert_refs: stream_refs(doc, dss, b"Certs")?,
        ocsp_refs: stream_refs(doc, dss, b"OCSPs")?,
        crl_refs: stream_refs(doc, dss, b"CRLs")?,
    })
}

fn merge_evidence_refs(
    doc: &lopdf::Document,
    existing: Vec<StreamRef>,
    new_blobs: &[Vec<u8>],
    next_id: &mut u32,
) -> Result<MergeRefs, PadesError> {
    let mut refs = Vec::new();
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for (id, bytes) in existing {
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        if !seen.contains(&hash) {
            seen.push(hash);
            refs.push(id);
        }
    }

    let mut new_streams = Vec::new();
    for blob in new_blobs {
        let hash: [u8; 32] = Sha256::digest(blob).into();
        if seen.contains(&hash) {
            continue;
        }
        let id = allocate_ids(next_id, 1)[0];
        seen.push(hash);
        refs.push(id);
        new_streams.push((id, blob.clone()));
    }

    for id in &refs {
        if doc.objects.contains_key(&(*id, 0)) || new_streams.iter().any(|(new_id, _)| new_id == id)
        {
            continue;
        }
        return Err(PadesError::MalformedStructure(format!(
            "DSS stream reference {id} 0 R is missing"
        )));
    }
    Ok((refs, new_streams))
}

fn reference_array(ids: &[u32]) -> lopdf::Object {
    lopdf::Object::Array(
        ids.iter()
            .map(|id| lopdf::Object::Reference((*id, 0)))
            .collect(),
    )
}

fn stream_body(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("<< /Length {} >>\nstream\n", bytes.len()).as_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\nendstream");
    out
}

fn incremental_section(
    prev_len: usize,
    prev_startxref: usize,
    root_id: u32,
    max_new_id: u32,
    objects: Vec<(u32, Vec<u8>)>,
) -> Vec<u8> {
    let mut section = Vec::new();
    section.push(b'\n');
    let mut offsets = Vec::new();

    for (id, body) in &objects {
        let off = prev_len + section.len();
        offsets.push((*id, off));
        section.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        section.extend_from_slice(body);
        section.extend_from_slice(b"\nendobj\n");
    }

    let xref_off = prev_len + section.len();
    section.extend_from_slice(b"xref\n");
    offsets.sort_by_key(|(id, _)| *id);
    let mut i = 0;
    while i < offsets.len() {
        let start_id = offsets[i].0;
        let mut j = i;
        while j + 1 < offsets.len() && offsets[j + 1].0 == offsets[j].0 + 1 {
            j += 1;
        }
        let count = j - i + 1;
        section.extend_from_slice(format!("{start_id} {count}\n").as_bytes());
        for (_, off) in &offsets[i..=j] {
            section.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
        }
        i = j + 1;
    }

    section.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root {root_id} 0 R /Prev {prev_startxref} >>\n",
            max_new_id + 1
        )
        .as_bytes(),
    );
    section.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    section
}

fn stream_hashes(
    doc: &lopdf::Document,
    dss: &lopdf::Dictionary,
    key: &[u8],
) -> Result<Vec<[u8; 32]>, PadesError> {
    let Some(array_obj) = dss.get(key).ok() else {
        return Ok(Vec::new());
    };
    let (_, array_obj) = doc.dereference(array_obj).map_err(|e| {
        PadesError::MalformedStructure(format!(
            "DSS /{} reference is invalid: {e}",
            String::from_utf8_lossy(key)
        ))
    })?;
    let array = array_obj.as_array().map_err(|_| {
        PadesError::MalformedStructure(format!(
            "DSS /{} is not an array",
            String::from_utf8_lossy(key)
        ))
    })?;
    let mut hashes = Vec::with_capacity(array.len());
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
        hashes.push(Sha256::digest(&stream.content).into());
    }
    Ok(hashes)
}

fn stream_refs(
    doc: &lopdf::Document,
    dss: &lopdf::Dictionary,
    key: &[u8],
) -> Result<Vec<StreamRef>, PadesError> {
    let Some(array_obj) = dss.get(key).ok() else {
        return Ok(Vec::new());
    };
    let (_, array_obj) = doc.dereference(array_obj).map_err(|e| {
        PadesError::MalformedStructure(format!(
            "DSS /{} reference is invalid: {e}",
            String::from_utf8_lossy(key)
        ))
    })?;
    let array = array_obj.as_array().map_err(|_| {
        PadesError::MalformedStructure(format!(
            "DSS /{} is not an array",
            String::from_utf8_lossy(key)
        ))
    })?;

    let mut refs = Vec::with_capacity(array.len());
    for item in array {
        let id = item.as_reference().map_err(|_| {
            PadesError::MalformedStructure(format!(
                "DSS /{} entry is not an indirect reference",
                String::from_utf8_lossy(key)
            ))
        })?;
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
        refs.push((id.0, stream.content.clone()));
    }
    Ok(refs)
}
