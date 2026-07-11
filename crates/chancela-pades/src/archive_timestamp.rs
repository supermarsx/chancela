//! Caller-supplied PAdES document timestamp incremental updates.
//!
//! This module appends and reports a technical `/DocTimeStamp` revision. It verifies the RFC 3161
//! message imprint against the timestamp dictionary's `/ByteRange` bytes where the token is a
//! SHA-256 `TimeStampToken`. It deliberately does not validate TSA signer/path trust, decide
//! renewal policy, or claim PAdES-B-LTA / legal LTV sufficiency.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_tsp::TstInfo;

use crate::error::PadesError;
use crate::pdf;

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// Bytes reserved for a produced `/DocTimeStamp` token inside its `/Contents` hex placeholder when
/// the token is not known up front (the [`add_doc_timestamp_revision_with`] production path). A
/// qualified RFC 3161 token that embeds the TSA certificate is a few KiB; 16 KiB leaves headroom.
pub const MAX_DOC_TIMESTAMP_TOKEN_BYTES: usize = 16 * 1024;

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
    /// Per-token semantic validation of the RFC 3161 imprint against the timestamped PDF revision.
    pub validations: Vec<DocTimeStampValidation>,
}

impl DocTimeStampReport {
    /// Number of document timestamp token blobs found.
    pub fn token_count(&self) -> usize {
        self.token_hashes.len()
    }

    /// Whether every discovered document timestamp has a valid SHA-256 imprint binding.
    pub fn all_imprints_valid(&self) -> bool {
        self.present
            && self.validations.len() == self.count
            && self
                .validations
                .iter()
                .all(|v| v.status == DocTimeStampSemanticStatus::Valid)
    }
}

/// Semantic validation result for one `/DocTimeStamp` token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DocTimeStampValidation {
    /// Zero-based position after sorting `/DocTimeStamp` dictionaries by object id.
    pub index: usize,
    /// PDF object id of the `/DocTimeStamp` dictionary.
    pub object_id: (u32, u16),
    /// Parsed `/ByteRange`, when available and well-typed.
    pub byte_range: Option<[i64; 4]>,
    /// SHA-256 digest over the bytes selected by `/ByteRange`, excluding `/Contents`.
    pub document_digest: Option<[u8; 32]>,
    /// Digest carried by `TSTInfo.messageImprint.hashedMessage`.
    pub token_imprint: Option<Vec<u8>>,
    /// Hash algorithm OID carried by `TSTInfo.messageImprint.hashAlgorithm`.
    pub token_hash_algorithm: Option<String>,
    /// High-level semantic status.
    pub status: DocTimeStampSemanticStatus,
    /// Machine-readable failure/boundary reason when `status` is not `Valid`.
    pub failure_reason: Option<DocTimeStampFailureReason>,
}

/// High-level `/DocTimeStamp` semantic status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DocTimeStampSemanticStatus {
    /// The RFC 3161 token imprint matches the SHA-256 digest of the indicated PDF revision bytes.
    Valid,
    /// The token or PDF timestamp metadata is malformed or the imprint does not match.
    Failed,
    /// The token uses a construction this PAdES layer does not validate semantically.
    Unsupported,
}

/// Machine-readable semantic validation failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DocTimeStampFailureReason {
    /// `/ByteRange` is absent from the timestamp dictionary.
    MissingByteRange,
    /// `/ByteRange` is not four non-negative integers within the file.
    InvalidByteRange,
    /// `/Contents` is absent or is not a complete DER `TimeStampToken`.
    InvalidContents,
    /// The token is not a CMS `SignedData` `ContentInfo`.
    NotSignedData,
    /// The token's encapsulated content is not `id-ct-TSTInfo`.
    NotTstInfo,
    /// The token has no encapsulated `TSTInfo` bytes.
    EmptyTstInfo,
    /// The token or `TSTInfo` could not be decoded as DER.
    MalformedToken,
    /// The token imprint uses a hash algorithm other than SHA-256.
    UnsupportedHashAlgorithm,
    /// The SHA-256 imprint in the token does not match the PDF revision digest.
    ImprintMismatch,
}

/// Append a `/DocTimeStamp` incremental update using caller-supplied RFC 3161 token bytes.
///
/// The token is embedded as `/SubFilter /ETSI.RFC3161` in a new signature dictionary. The
/// `/ByteRange` covers the resulting PDF revision except the timestamp token's `/Contents`
/// placeholder. Call [`inspect_doc_timestamps`] or [`crate::validate_pdf_signature`] to verify
/// that the token's RFC 3161 message imprint attests that digest. TSA signer/path trust remains a
/// higher-layer follow-up and no B-LTA/legal LTV claim is made here.
pub fn add_doc_timestamp_revision(
    pdf_bytes: &[u8],
    timestamp_token_der: &[u8],
) -> Result<Vec<u8>, PadesError> {
    validate_token(timestamp_token_der)?;

    // The token is known up front, so the placeholder is sized to it exactly.
    let capacity = timestamp_token_der.len().max(1);
    let placeholder = build_doc_timestamp_placeholder(pdf_bytes, capacity)?;
    let mut out = placeholder.pdf;
    let hex = pdf::to_hex(timestamp_token_der);
    out[placeholder.hex_start..placeholder.hex_start + hex.len()].copy_from_slice(&hex);
    Ok(out)
}

/// Produce and append a `/DocTimeStamp` archive timestamp over the resulting PDF revision (SIG-22).
///
/// This is the production counterpart of [`add_doc_timestamp_revision`]: instead of taking a
/// pre-built token, it lays out a fixed-size (`MAX_DOC_TIMESTAMP_TOKEN_BYTES`) `/Contents`
/// placeholder, computes the SHA-256 digest over the new revision's `/ByteRange` (everything except
/// that placeholder), and hands it to `produce_token`, which must return an RFC 3161
/// `TimeStampToken` DER whose message imprint attests exactly that digest — e.g. by asking a TSA to
/// timestamp the digest. The returned token is embedded into the placeholder, so the resulting
/// `/DocTimeStamp` validates in [`inspect_doc_timestamps`] / [`crate::validate_pdf_signature`].
///
/// This appends real archive-timestamp evidence over the document (the "A" in PAdES-B-LTA). It does
/// not by itself validate TSA signer/path trust or the underlying revocation material — that trust
/// evaluation, and any long-term/legal sufficiency claim, remains a higher-layer decision.
pub fn add_doc_timestamp_revision_with<F, E>(
    pdf_bytes: &[u8],
    produce_token: F,
) -> Result<Vec<u8>, PadesError>
where
    F: FnOnce(&[u8; 32]) -> Result<Vec<u8>, E>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let placeholder = build_doc_timestamp_placeholder(pdf_bytes, MAX_DOC_TIMESTAMP_TOKEN_BYTES)?;
    let token = produce_token(&placeholder.byterange_digest)
        .map_err(|e| PadesError::Timestamp(e.into()))?;
    validate_token(&token)?;
    if token.len() > MAX_DOC_TIMESTAMP_TOKEN_BYTES {
        return Err(PadesError::ContentsPlaceholderTooSmall {
            produced: token.len(),
            capacity: MAX_DOC_TIMESTAMP_TOKEN_BYTES,
        });
    }

    let mut out = placeholder.pdf;
    // Reset the whole reserved gap to '0' (the token may be shorter than the reservation), then
    // write the token hex over the prefix. The gap is excluded from `/ByteRange`, so the digest the
    // token attests is unaffected.
    for b in &mut out[placeholder.hex_start..placeholder.gt] {
        *b = b'0';
    }
    let hex = pdf::to_hex(&token);
    out[placeholder.hex_start..placeholder.hex_start + hex.len()].copy_from_slice(&hex);
    Ok(out)
}

/// A `/DocTimeStamp` incremental revision with a zero-filled `/Contents` placeholder of `capacity`
/// bytes, its `/ByteRange` patched, and the digest an RFC 3161 token must attest already computed.
struct DocTimeStampPlaceholder {
    /// Full document bytes: original + incremental revision, `/Contents` still zero-filled.
    pdf: Vec<u8>,
    /// Index of the first hex character inside `/Contents <...>` (one past the `<`).
    hex_start: usize,
    /// Index of the closing `>` of the `/Contents` placeholder.
    gt: usize,
    /// SHA-256 over the bytes selected by `/ByteRange` (everything except the placeholder).
    byterange_digest: [u8; 32],
}

/// Build the `/DocTimeStamp` incremental revision and reserve a `capacity`-byte `/Contents`
/// placeholder, patching the `/ByteRange` and computing the digest the eventual token must cover.
fn build_doc_timestamp_placeholder(
    pdf_bytes: &[u8],
    capacity: usize,
) -> Result<DocTimeStampPlaceholder, PadesError> {
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
    let sig_body = doc_timestamp_dict_template(capacity);

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
    let gt = hex_start + capacity * 2;
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

    let mut hasher = Sha256::new();
    hasher.update(&out[0..lt]);
    hasher.update(&out[range2_start..range2_start + range2_len]);
    let byterange_digest: [u8; 32] = hasher.finalize().into();

    Ok(DocTimeStampPlaceholder {
        pdf: out,
        hex_start,
        gt,
        byterange_digest,
    })
}

/// Inspect `/DocTimeStamp` dictionaries and hash their embedded token bytes.
pub fn inspect_doc_timestamps(pdf_bytes: &[u8]) -> Result<DocTimeStampReport, PadesError> {
    let doc =
        lopdf::Document::load_mem(pdf_bytes).map_err(|e| PadesError::PdfParse(e.to_string()))?;
    inspect_doc_timestamps_document(&doc, pdf_bytes)
}

pub(crate) fn inspect_doc_timestamps_document(
    doc: &lopdf::Document,
    pdf_bytes: &[u8],
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
    let mut validations = Vec::new();
    for (index, (object_id, dict)) in entries.iter().enumerate() {
        let token = decoded_timestamp_token(dict);
        if let Ok(token) = token {
            token_hashes.push(Sha256::digest(token).into());
        }
        validations.push(validate_doc_timestamp(
            index, *object_id, dict, pdf_bytes, token,
        ));
    }

    Ok(DocTimeStampReport {
        present: !entries.is_empty(),
        count: entries.len(),
        token_hashes,
        validations,
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

fn validate_doc_timestamp(
    index: usize,
    object_id: (u32, u16),
    dict: &lopdf::Dictionary,
    pdf_bytes: &[u8],
    token: Result<&[u8], DocTimeStampFailureReason>,
) -> DocTimeStampValidation {
    let byte_range = match parse_byte_range(dict, pdf_bytes.len()) {
        Ok(range) => range,
        Err(reason) => {
            return DocTimeStampValidation {
                index,
                object_id,
                byte_range: None,
                document_digest: None,
                token_imprint: None,
                token_hash_algorithm: None,
                status: DocTimeStampSemanticStatus::Failed,
                failure_reason: Some(reason),
            };
        }
    };
    let document_digest = digest_byte_range(pdf_bytes, byte_range);
    let token = match token {
        Ok(token) => token,
        Err(reason) => {
            return DocTimeStampValidation {
                index,
                object_id,
                byte_range: Some(byte_range),
                document_digest: Some(document_digest),
                token_imprint: None,
                token_hash_algorithm: None,
                status: DocTimeStampSemanticStatus::Failed,
                failure_reason: Some(reason),
            };
        }
    };
    let imprint = match timestamp_token_imprint(token) {
        Ok(imprint) => imprint,
        Err(reason) => {
            return DocTimeStampValidation {
                index,
                object_id,
                byte_range: Some(byte_range),
                document_digest: Some(document_digest),
                token_imprint: None,
                token_hash_algorithm: None,
                status: match reason {
                    DocTimeStampFailureReason::UnsupportedHashAlgorithm => {
                        DocTimeStampSemanticStatus::Unsupported
                    }
                    _ => DocTimeStampSemanticStatus::Failed,
                },
                failure_reason: Some(reason),
            };
        }
    };

    let valid = imprint.hashed_message.as_slice() == document_digest;
    DocTimeStampValidation {
        index,
        object_id,
        byte_range: Some(byte_range),
        document_digest: Some(document_digest),
        token_imprint: Some(imprint.hashed_message),
        token_hash_algorithm: Some(imprint.hash_algorithm),
        status: if valid {
            DocTimeStampSemanticStatus::Valid
        } else {
            DocTimeStampSemanticStatus::Failed
        },
        failure_reason: if valid {
            None
        } else {
            Some(DocTimeStampFailureReason::ImprintMismatch)
        },
    }
}

#[derive(Debug)]
struct TimestampImprint {
    hash_algorithm: String,
    hashed_message: Vec<u8>,
}

fn timestamp_token_imprint(
    token_der: &[u8],
) -> Result<TimestampImprint, DocTimeStampFailureReason> {
    let ci =
        ContentInfo::from_der(token_der).map_err(|_| DocTimeStampFailureReason::MalformedToken)?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(DocTimeStampFailureReason::NotSignedData);
    }
    let signed_data_der = ci
        .content
        .to_der()
        .map_err(|_| DocTimeStampFailureReason::MalformedToken)?;
    let signed_data = SignedData::from_der(&signed_data_der)
        .map_err(|_| DocTimeStampFailureReason::MalformedToken)?;
    if signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(DocTimeStampFailureReason::NotTstInfo);
    }
    let tst_der = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(DocTimeStampFailureReason::EmptyTstInfo)?
        .value();
    let tst = TstInfo::from_der(tst_der).map_err(|_| DocTimeStampFailureReason::MalformedToken)?;
    let hash_algorithm = tst.message_imprint.hash_algorithm.oid.to_string();
    let hashed_message = tst.message_imprint.hashed_message.as_bytes().to_vec();
    if tst.message_imprint.hash_algorithm.oid != ID_SHA256 {
        return Err(DocTimeStampFailureReason::UnsupportedHashAlgorithm);
    }
    Ok(TimestampImprint {
        hash_algorithm,
        hashed_message,
    })
}

fn decoded_timestamp_token(dict: &lopdf::Dictionary) -> Result<&[u8], DocTimeStampFailureReason> {
    let contents = dict
        .get(b"Contents")
        .and_then(lopdf::Object::as_str)
        .map_err(|_| DocTimeStampFailureReason::InvalidContents)?;
    let len = pdf::der_total_len(contents).ok_or(DocTimeStampFailureReason::InvalidContents)?;
    if len > contents.len() {
        return Err(DocTimeStampFailureReason::InvalidContents);
    }
    Ok(&contents[..len])
}

fn parse_byte_range(
    dict: &lopdf::Dictionary,
    total_len: usize,
) -> Result<[i64; 4], DocTimeStampFailureReason> {
    let arr = dict
        .get(b"ByteRange")
        .and_then(lopdf::Object::as_array)
        .map_err(|_| DocTimeStampFailureReason::MissingByteRange)?;
    if arr.len() != 4 {
        return Err(DocTimeStampFailureReason::InvalidByteRange);
    }
    let mut byte_range = [0i64; 4];
    let mut ranges = [0usize; 4];
    for (i, item) in arr.iter().enumerate() {
        let value = item
            .as_i64()
            .map_err(|_| DocTimeStampFailureReason::InvalidByteRange)?;
        byte_range[i] = value;
        ranges[i] =
            usize::try_from(value).map_err(|_| DocTimeStampFailureReason::InvalidByteRange)?;
    }
    let [s1, l1, s2, l2] = ranges;
    if s1.checked_add(l1).map(|e| e > total_len).unwrap_or(true)
        || s2.checked_add(l2).map(|e| e > total_len).unwrap_or(true)
    {
        return Err(DocTimeStampFailureReason::InvalidByteRange);
    }
    Ok(byte_range)
}

fn digest_byte_range(pdf_bytes: &[u8], byte_range: [i64; 4]) -> [u8; 32] {
    let [s1, l1, s2, l2] = byte_range.map(|v| usize::try_from(v).expect("valid byte range"));
    let mut hasher = Sha256::new();
    hasher.update(&pdf_bytes[s1..s1 + l1]);
    hasher.update(&pdf_bytes[s2..s2 + l2]);
    hasher.finalize().into()
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
