//! Local, caller-supplied PAdES DSS/VRI incremental updates.
//!
//! This module deliberately does not fetch OCSP/CRL material, validate revocation freshness, or
//! claim legal B-LT sufficiency. It only embeds and reports caller-supplied DER evidence in a
//! deterministic `/DSS` revision so higher layers can preserve and describe the bytes.

use sha2::{Digest, Sha256};

use crate::error::PadesError;
use crate::pdf;

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
}

/// Append a deterministic `/DSS` incremental update to a signed PDF.
///
/// Existing DSS dictionaries are rejected in this first slice; merging and multi-signature VRI
/// updates are separate interoperability work. The VRI key is the lowercase SHA-256 hex digest of
/// the embedded CMS `/Contents` DER.
pub fn add_dss_revision(signed_pdf: &[u8], evidence: &DssEvidence) -> Result<Vec<u8>, PadesError> {
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
    if catalog.has(b"DSS") {
        return Err(PadesError::ExistingDssUnsupported);
    }

    let signature_der = first_signature_contents_der(&doc)?;
    let vri_key = pdf::to_hex(&Sha256::digest(&signature_der));

    let mut next_id = doc.max_id + 1;
    let dss_id = next_id;
    next_id += 1;
    let vri_id = next_id;
    next_id += 1;

    let cert_ids = allocate_ids(&mut next_id, evidence.certificates.len());
    let ocsp_ids = allocate_ids(&mut next_id, evidence.ocsp_responses.len());
    let crl_ids = allocate_ids(&mut next_id, evidence.crls.len());
    let max_new_id = next_id - 1;

    catalog.set("DSS", lopdf::Object::Reference((dss_id, 0)));
    let catalog_body = serialize_dict(&catalog)?;

    let dss_body = dss_dict_body(&vri_key, vri_id, &cert_ids, &ocsp_ids, &crl_ids)?;
    let vri_body = vri_dict_body(&cert_ids, &ocsp_ids, &crl_ids)?;

    let mut objects: Vec<(u32, Vec<u8>)> = vec![
        (root_id.0, catalog_body),
        (dss_id, dss_body),
        (vri_id, vri_body),
    ];
    objects.extend(
        cert_ids
            .iter()
            .zip(&evidence.certificates)
            .map(|(id, bytes)| (*id, stream_body(bytes))),
    );
    objects.extend(
        ocsp_ids
            .iter()
            .zip(&evidence.ocsp_responses)
            .map(|(id, bytes)| (*id, stream_body(bytes))),
    );
    objects.extend(
        crl_ids
            .iter()
            .zip(&evidence.crls)
            .map(|(id, bytes)| (*id, stream_body(bytes))),
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

    let vri_count = match dss.get(b"VRI").ok() {
        Some(vri_obj) => {
            let (_, vri_obj) = doc.dereference(vri_obj).map_err(|e| {
                PadesError::MalformedStructure(format!("DSS /VRI reference is invalid: {e}"))
            })?;
            vri_obj
                .as_dict()
                .map_err(|_| PadesError::MalformedStructure("DSS /VRI is not a dictionary".into()))?
                .len()
        }
        None => 0,
    };

    Ok(DssReport {
        present: true,
        vri_count,
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

fn first_signature_contents_der(doc: &lopdf::Document) -> Result<Vec<u8>, PadesError> {
    let sig = doc
        .objects
        .values()
        .filter_map(|o| o.as_dict().ok())
        .find(|d| d.get_type().map(|t| t == b"Sig").unwrap_or(false))
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
    vri_key: &[u8],
    vri_id: u32,
    cert_ids: &[u32],
    ocsp_ids: &[u32],
    crl_ids: &[u32],
) -> Result<Vec<u8>, PadesError> {
    let mut vri = lopdf::Dictionary::new();
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
    serialize_dict(&vri)
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
