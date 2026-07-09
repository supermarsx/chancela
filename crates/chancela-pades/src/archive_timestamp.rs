//! Caller-supplied PAdES document timestamp incremental updates.
//!
//! This module appends and reports a technical `/DocTimeStamp` revision. It deliberately does not
//! validate RFC 3161 semantics, decide renewal policy, or claim PAdES-B-LTA / legal LTV
//! sufficiency.

use sha2::{Digest, Sha256};

use crate::error::PadesError;
use crate::pdf;

/// Technical report for embedded PAdES document timestamps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DocTimeStampReport {
    /// Whether at least one `/Type /DocTimeStamp` signature dictionary is present.
    pub present: bool,
    /// Number of `/DocTimeStamp` dictionaries found in the latest PDF object graph.
    pub count: usize,
    /// SHA-256 hashes of decoded `/DocTimeStamp /Contents` token bytes, in object-id order.
    pub token_hashes: Vec<[u8; 32]>,
}

impl DocTimeStampReport {
    /// Number of document timestamp token blobs found.
    pub fn token_count(&self) -> usize {
        self.token_hashes.len()
    }
}

/// Append a `/DocTimeStamp` incremental update using caller-supplied RFC 3161 token bytes.
///
/// The token is embedded as `/SubFilter /ETSI.RFC3161` in a new signature dictionary. The
/// `/ByteRange` covers the resulting PDF revision except the timestamp token's `/Contents`
/// placeholder, but this function does not verify that the token attests that digest.
pub fn add_doc_timestamp_revision(
    pdf_bytes: &[u8],
    timestamp_token_der: &[u8],
) -> Result<Vec<u8>, PadesError> {
    validate_token(timestamp_token_der)?;

    let doc =
        lopdf::Document::load_mem(pdf_bytes).map_err(|e| PadesError::PdfParse(e.to_string()))?;
    let prev_startxref = pdf::last_startxref(pdf_bytes).ok_or(PadesError::MissingStartxref)?;
    if pdf_bytes.get(prev_startxref..prev_startxref + 4) != Some(b"xref") {
        return Err(PadesError::MalformedStructure(
            "input PDF uses cross-reference streams; a classic xref table is required".into(),
        ));
    }

    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .map_err(|_| PadesError::MalformedStructure("trailer has no /Root reference".into()))?;
    let catalog = doc
        .get_object(root_id)
        .and_then(lopdf::Object::as_dict)
        .map_err(|_| PadesError::MalformedStructure("catalog object missing".into()))?;
    let acroform_id = catalog
        .get(b"AcroForm")
        .and_then(lopdf::Object::as_reference)
        .map_err(|_| {
            PadesError::MalformedStructure(
                "document timestamp append requires an existing PAdES AcroForm".into(),
            )
        })?;
    let mut acroform = doc
        .get_object(acroform_id)
        .and_then(lopdf::Object::as_dict)
        .map_err(|_| PadesError::MalformedStructure("AcroForm object missing".into()))?
        .clone();

    let mut fields = acroform
        .get(b"Fields")
        .and_then(lopdf::Object::as_array)
        .map_err(|_| PadesError::MalformedStructure("AcroForm /Fields is missing".into()))?
        .clone();

    let field_id = doc.max_id + 1;
    let timestamp_id = doc.max_id + 2;
    fields.push(lopdf::Object::Reference((field_id, 0)));
    acroform.set("Fields", lopdf::Object::Array(fields));
    acroform.set("SigFlags", lopdf::Object::Integer(3));

    let acroform_body = serialize_dict(&acroform)?;
    let field_body = doc_timestamp_field_body(timestamp_id)?;
    let token_capacity = timestamp_token_der.len().max(1);
    let sig_body = doc_timestamp_dict_template(token_capacity);

    let mut section = incremental_section(
        pdf_bytes.len(),
        prev_startxref,
        root_id.0,
        timestamp_id,
        vec![
            (acroform_id.0, acroform_body),
            (field_id, field_body),
            (timestamp_id, sig_body),
        ],
    );

    let mut out = pdf_bytes.to_vec();
    out.append(&mut section);

    let lt = pdf::rfind(&out, b"/Contents <")
        .ok_or_else(|| PadesError::MalformedStructure("DocTimeStamp contents not found".into()))?
        + b"/Contents ".len();
    let hex_start = lt + 1;
    let gt = hex_start + token_capacity * 2;
    if out.get(gt) != Some(&b'>') {
        return Err(PadesError::MalformedStructure(
            "DocTimeStamp contents placeholder is malformed".into(),
        ));
    }
    let range2_start = gt + 1;
    let range2_len = out.len() - range2_start;
    let br_marker = pdf::rfind(&out, b"/ByteRange [0 ")
        .ok_or_else(|| PadesError::MalformedStructure("DocTimeStamp ByteRange not found".into()))?
        + b"/ByteRange [0 ".len();
    let br = format!("{lt:010} {range2_start:010} {range2_len:010}");
    out[br_marker..br_marker + br.len()].copy_from_slice(br.as_bytes());

    let hex = pdf::to_hex(timestamp_token_der);
    out[hex_start..hex_start + hex.len()].copy_from_slice(&hex);
    Ok(out)
}

/// Inspect `/DocTimeStamp` dictionaries and hash their embedded token bytes.
pub fn inspect_doc_timestamps(pdf_bytes: &[u8]) -> Result<DocTimeStampReport, PadesError> {
    let doc =
        lopdf::Document::load_mem(pdf_bytes).map_err(|e| PadesError::PdfParse(e.to_string()))?;
    inspect_doc_timestamps_document(&doc)
}

pub(crate) fn inspect_doc_timestamps_document(
    doc: &lopdf::Document,
) -> Result<DocTimeStampReport, PadesError> {
    let mut entries: Vec<_> = doc
        .objects
        .iter()
        .filter_map(|(id, obj)| {
            let dict = obj.as_dict().ok()?;
            dict.get_type().ok().filter(|ty| *ty == b"DocTimeStamp")?;
            Some((*id, dict))
        })
        .collect();
    entries.sort_by_key(|(id, _)| *id);

    let mut token_hashes = Vec::new();
    for (_, dict) in &entries {
        let contents = dict
            .get(b"Contents")
            .and_then(lopdf::Object::as_str)
            .map_err(|_| PadesError::InvalidDocTimeStampToken)?;
        let len = pdf::der_total_len(contents).ok_or(PadesError::InvalidDocTimeStampToken)?;
        if len > contents.len() {
            return Err(PadesError::InvalidDocTimeStampToken);
        }
        token_hashes.push(Sha256::digest(&contents[..len]).into());
    }

    Ok(DocTimeStampReport {
        present: !entries.is_empty(),
        count: entries.len(),
        token_hashes,
    })
}

fn validate_token(timestamp_token_der: &[u8]) -> Result<(), PadesError> {
    if timestamp_token_der.is_empty()
        || pdf::der_total_len(timestamp_token_der) != Some(timestamp_token_der.len())
    {
        return Err(PadesError::InvalidDocTimeStampToken);
    }
    Ok(())
}

fn serialize_dict(dict: &lopdf::Dictionary) -> Result<Vec<u8>, PadesError> {
    let mut out = Vec::new();
    pdf::write_dict(dict, &mut out).map_err(|m| PadesError::MalformedStructure(m.into()))?;
    Ok(out)
}

fn doc_timestamp_field_body(timestamp_id: u32) -> Result<Vec<u8>, PadesError> {
    let mut field = lopdf::Dictionary::new();
    field.set("FT", lopdf::Object::Name(b"Sig".to_vec()));
    field.set(
        "T",
        lopdf::Object::String(b"DocTimeStamp1".to_vec(), lopdf::StringFormat::Literal),
    );
    field.set("V", lopdf::Object::Reference((timestamp_id, 0)));
    serialize_dict(&field)
}

fn doc_timestamp_dict_template(token_capacity: usize) -> Vec<u8> {
    let mut body = b"<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /ByteRange [0 0000000000 0000000000 0000000000] /Contents <".to_vec();
    body.extend(std::iter::repeat_n(b'0', token_capacity * 2));
    body.extend_from_slice(b"> >>");
    body
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
