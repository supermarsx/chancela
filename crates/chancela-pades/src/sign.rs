//! PAdES-B-B signing by incremental update, plus PAdES-B-T signature-timestamp embedding.
//!
//! Signing an existing PDF appends an incremental-update section that adds an AcroForm signature
//! field and a `/Sig` dictionary. The `/Contents` entry is a fixed-size zero-filled hex placeholder
//! excluded from the `/ByteRange`; we compute the ByteRange around it, hash the covered bytes with
//! SHA-256, hand that digest to the caller's signing callback (which builds the detached CMS via
//! `chancela-cades`), and hex-fill the CMS into the placeholder.
//!
//! B-T ([`add_signature_timestamp`]) parses a freshly signed PDF, computes the SHA-256 of the CMS
//! signature value, obtains an RFC 3161 token (via `chancela-tsa`) over it, and inserts it as the
//! `id-aa-signatureTimeStampToken` unsigned attribute — re-embedding into the same placeholder,
//! which leaves the ByteRange (and therefore the B-B signature) untouched.

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfos, UnsignedAttributes};
use der::asn1::{Any, ObjectIdentifier, SetOfVec};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::attr::Attribute;

use crate::error::PadesError;
use crate::pdf;

/// Bytes reserved for the CMS inside the `/Contents` hex placeholder. A CAdES-B CMS (2048-bit RSA
/// or P-256 signature + signer certificate) is a few KB; a signature timestamp adds a couple more.
/// 16 KiB leaves generous headroom for B-B and B-T.
pub const MAX_CONTENTS_BYTES: usize = 16 * 1024;

/// Length of the `/Contents` hex placeholder (two hex chars per reserved byte).
const CONTENTS_HEX_LEN: usize = MAX_CONTENTS_BYTES * 2;

/// OID `id-aa-signatureTimeStampToken` (RFC 3161 / ETSI EN 319 122) — the CMS unsigned attribute
/// that carries a PAdES-B-T signature timestamp.
const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// Options controlling the signature dictionary. All fields are optional and cosmetic — the
/// authoritative signing time and certificate binding live in the CAdES signed attributes.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// The AcroForm signature field name (`/T`). Defaults to `"Signature1"`.
    pub field_name: Option<String>,
    /// `/M` signing time string, e.g. `"D:20260706142640Z"`.
    pub signing_time: Option<String>,
    /// `/Reason` for signing.
    pub reason: Option<String>,
    /// `/Location` of signing.
    pub location: Option<String>,
    /// `/ContactInfo` for the signer.
    pub contact_info: Option<String>,
}

/// The result of preparing the incremental update: the assembled bytes with a placeholder
/// `/Contents`, the ByteRange digest to sign, and the byte span of the hex placeholder.
struct Prepared {
    /// The full document bytes, ByteRange already patched, `/Contents` still zero-filled.
    bytes: Vec<u8>,
    /// SHA-256 over the ByteRange-covered bytes.
    content_digest: [u8; 32],
    /// Index of the first hex character inside `<...>` (one past the `<`).
    hex_start: usize,
}

/// Sign an existing PDF, producing a PAdES-B-B signature (SIG-21).
///
/// `sign_cms` receives the SHA-256 of the ByteRange-covered bytes and must return a detached CMS
/// (a DER `ContentInfo` wrapping a CAdES-B `SignedData`) over that digest — typically built with
/// `chancela_cades::assemble_cades_b`. The returned bytes are the original PDF plus one incremental
/// update carrying the signature.
pub fn sign_pdf<S, E>(
    pdf_bytes: &[u8],
    opts: &SignOptions,
    sign_cms: S,
) -> Result<Vec<u8>, PadesError>
where
    S: FnOnce(&[u8; 32]) -> Result<Vec<u8>, E>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let prepared = prepare_incremental(pdf_bytes, opts)?;
    let cms = sign_cms(&prepared.content_digest).map_err(|e| PadesError::Signer(e.into()))?;
    embed_cms(prepared.bytes, prepared.hex_start, &cms)
}

/// Build the incremental-update section: clone/override the catalog and page, add the AcroForm,
/// signature field, and `/Sig` dictionary, assemble the bytes, patch the `/ByteRange`, and compute
/// the digest over the covered ranges.
fn prepare_incremental(pdf_bytes: &[u8], opts: &SignOptions) -> Result<Prepared, PadesError> {
    let doc =
        lopdf::Document::load_mem(pdf_bytes).map_err(|e| PadesError::PdfParse(e.to_string()))?;

    let prev_startxref = pdf::last_startxref(pdf_bytes).ok_or(PadesError::MissingStartxref)?;
    // Only classic cross-reference tables can be chained by a classic incremental xref.
    if pdf_bytes.get(prev_startxref..prev_startxref + 4) != Some(b"xref") {
        return Err(PadesError::MalformedStructure(
            "input PDF uses cross-reference streams; a classic xref table is required (phase-1 \
             limitation)"
                .into(),
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
    if catalog.has(b"AcroForm") {
        return Err(PadesError::MalformedStructure(
            "PDF already has an AcroForm; adding to an existing form is not supported (phase-1)"
                .into(),
        ));
    }

    let pages_id = catalog
        .get(b"Pages")
        .and_then(lopdf::Object::as_reference)
        .map_err(|_| PadesError::MalformedStructure("catalog has no /Pages".into()))?;
    let pages = doc
        .get_object(pages_id)
        .and_then(lopdf::Object::as_dict)
        .map_err(|_| PadesError::MalformedStructure("pages tree missing".into()))?;
    let page_id = pages
        .get(b"Kids")
        .and_then(lopdf::Object::as_array)
        .ok()
        .and_then(|kids| kids.first())
        .and_then(|k| k.as_reference().ok())
        .ok_or_else(|| PadesError::MalformedStructure("no page in /Kids".into()))?;
    let mut page = doc
        .get_object(page_id)
        .and_then(lopdf::Object::as_dict)
        .map_err(|_| PadesError::MalformedStructure("page object missing".into()))?
        .clone();

    // Allocate new object numbers above the current maximum.
    let base = doc.max_id;
    let af_num = base + 1;
    let field_num = base + 2;
    let sig_num = base + 3;

    // Catalog gains the AcroForm.
    catalog.set("AcroForm", lopdf::Object::Reference((af_num, 0)));

    // Page gains the signature widget in /Annots (must be an inline array in phase-1).
    let annots = match page.get(b"Annots") {
        Ok(lopdf::Object::Array(existing)) => {
            let mut a = existing.clone();
            a.push(lopdf::Object::Reference((field_num, 0)));
            a
        }
        Ok(_) => {
            return Err(PadesError::MalformedStructure(
                "page /Annots is an indirect reference; inline array required (phase-1)".into(),
            ));
        }
        Err(_) => vec![lopdf::Object::Reference((field_num, 0))],
    };
    page.set("Annots", lopdf::Object::Array(annots));

    // AcroForm dictionary.
    let mut acroform = lopdf::Dictionary::new();
    acroform.set(
        "Fields",
        lopdf::Object::Array(vec![lopdf::Object::Reference((field_num, 0))]),
    );
    acroform.set("SigFlags", lopdf::Object::Integer(3));

    // Signature field (merged widget annotation).
    let field_name = opts.field_name.as_deref().unwrap_or("Signature1");
    let mut field = lopdf::Dictionary::new();
    field.set("FT", lopdf::Object::Name(b"Sig".to_vec()));
    field.set(
        "T",
        lopdf::Object::String(field_name.as_bytes().to_vec(), lopdf::StringFormat::Literal),
    );
    field.set("V", lopdf::Object::Reference((sig_num, 0)));
    field.set("Type", lopdf::Object::Name(b"Annot".to_vec()));
    field.set("Subtype", lopdf::Object::Name(b"Widget".to_vec()));
    // /F 132 = Print (4) + Locked (128): an invisible, locked signature widget.
    field.set("F", lopdf::Object::Integer(132));
    field.set(
        "Rect",
        lopdf::Object::Array(vec![
            lopdf::Object::Integer(0),
            lopdf::Object::Integer(0),
            lopdf::Object::Integer(0),
            lopdf::Object::Integer(0),
        ]),
    );
    field.set("P", lopdf::Object::Reference((page_id.0, page_id.1)));

    // Serialize the overriding / new objects.
    let ser = |d: &lopdf::Dictionary| -> Result<Vec<u8>, PadesError> {
        let mut v = Vec::new();
        pdf::write_dict(d, &mut v).map_err(|m| PadesError::MalformedStructure(m.into()))?;
        Ok(v)
    };
    let catalog_body = ser(&catalog)?;
    let page_body = ser(&page)?;
    let acroform_body = ser(&acroform)?;
    let field_body = ser(&field)?;
    let sig_body = signature_dict_template(opts);

    // Assemble the incremental section, recording each object's absolute offset.
    let prev_len = pdf_bytes.len();
    let mut section: Vec<u8> = Vec::new();
    section.push(b'\n');
    let mut offsets: Vec<(u32, usize)> = Vec::new();

    let objects: [(u32, &[u8]); 5] = [
        (root_id.0, &catalog_body),
        (page_id.0, &page_body),
        (af_num, &acroform_body),
        (field_num, &field_body),
        (sig_num, &sig_body),
    ];
    for (id, body) in objects {
        let off = prev_len + section.len();
        offsets.push((id, off));
        section.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        section.extend_from_slice(body);
        section.extend_from_slice(b"\nendobj\n");
    }

    // Cross-reference table (subsections grouped by consecutive object number).
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
            // Each entry is exactly 20 bytes: "nnnnnnnnnn 00000 n\r\n".
            section.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
        }
        i = j + 1;
    }

    // Trailer + startxref.
    let size = sig_num + 1;
    section.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root {} 0 R /Prev {prev_startxref} >>\n",
            root_id.0
        )
        .as_bytes(),
    );
    section.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());

    // Full document = original + incremental section.
    let mut bytes = pdf_bytes.to_vec();
    bytes.extend_from_slice(&section);

    // Locate the /Contents placeholder and compute the ByteRange around it.
    let lt = pdf::find(&bytes, b"/Contents <")
        .ok_or_else(|| PadesError::MalformedStructure("contents placeholder not found".into()))?
        + b"/Contents ".len(); // index of '<'
    let hex_start = lt + 1;
    let gt = hex_start + CONTENTS_HEX_LEN; // index of '>'
    debug_assert_eq!(bytes.get(gt), Some(&b'>'));

    let total = bytes.len();
    let range1_len = lt; // [0, lt)
    let range2_start = gt + 1; // first byte after '>'
    let range2_len = total - range2_start;

    // Patch the fixed-width ByteRange placeholder in place (widths are preserved, so no offset
    // shifts). The array is "[0 0000000000 0000000000 0000000000]".
    let br_marker = pdf::find(&bytes, b"/ByteRange [0 ")
        .ok_or_else(|| PadesError::MalformedStructure("ByteRange placeholder not found".into()))?
        + b"/ByteRange [0 ".len();
    let br = format!("{range1_len:010} {range2_start:010} {range2_len:010}");
    debug_assert_eq!(br.len(), 32);
    bytes[br_marker..br_marker + br.len()].copy_from_slice(br.as_bytes());

    // Digest over the covered ranges (ByteRange is now final).
    let mut hasher = Sha256::new();
    hasher.update(&bytes[0..range1_len]);
    hasher.update(&bytes[range2_start..range2_start + range2_len]);
    let content_digest: [u8; 32] = hasher.finalize().into();

    Ok(Prepared {
        bytes,
        content_digest,
        hex_start,
    })
}

/// Build the raw `/Sig` dictionary body with a fixed-width ByteRange placeholder and a zero-filled
/// `/Contents` hex placeholder. Serialized by hand so `/Contents` sits last and its byte position
/// is deterministic.
fn signature_dict_template(opts: &SignOptions) -> Vec<u8> {
    let mut s = String::new();
    s.push_str("<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached");
    let literal = |k: &str, v: &str, s: &mut String| {
        s.push_str(" /");
        s.push_str(k);
        s.push_str(" (");
        for c in v.chars() {
            if matches!(c, '(' | ')' | '\\') {
                s.push('\\');
            }
            s.push(c);
        }
        s.push(')');
    };
    if let Some(m) = &opts.signing_time {
        literal("M", m, &mut s);
    }
    if let Some(r) = &opts.reason {
        literal("Reason", r, &mut s);
    }
    if let Some(l) = &opts.location {
        literal("Location", l, &mut s);
    }
    if let Some(c) = &opts.contact_info {
        literal("ContactInfo", c, &mut s);
    }
    s.push_str(" /ByteRange [0 0000000000 0000000000 0000000000]");
    s.push_str(" /Contents <");
    let mut body = s.into_bytes();
    body.extend(std::iter::repeat_n(b'0', CONTENTS_HEX_LEN));
    body.extend_from_slice(b"> >>");
    body
}

/// Hex-fill a CMS into the `/Contents` placeholder starting at `hex_start`, zero-padding the
/// remainder. `hex_start..hex_start+CONTENTS_HEX_LEN` must already be the zero-filled placeholder.
fn embed_cms(mut bytes: Vec<u8>, hex_start: usize, cms: &[u8]) -> Result<Vec<u8>, PadesError> {
    if cms.len() > MAX_CONTENTS_BYTES {
        return Err(PadesError::ContentsPlaceholderTooSmall {
            produced: cms.len(),
            capacity: MAX_CONTENTS_BYTES,
        });
    }
    // Reset the whole gap to '0', then write the CMS hex over the prefix.
    for b in &mut bytes[hex_start..hex_start + CONTENTS_HEX_LEN] {
        *b = b'0';
    }
    let hex = pdf::to_hex(cms);
    bytes[hex_start..hex_start + hex.len()].copy_from_slice(&hex);
    Ok(bytes)
}

/// Add a PAdES-B-T signature timestamp to an already B-B-signed PDF (SIG-22).
///
/// `timestamp` receives the SHA-256 of the CMS signature value and must return an RFC 3161
/// [`chancela_tsa::Timestamp`] over it. The token is inserted as the `id-aa-signatureTimeStampToken`
/// unsigned attribute and the CMS is re-embedded into the existing `/Contents` placeholder, leaving
/// the `/ByteRange` — and therefore the B-B signature — unchanged.
pub fn add_signature_timestamp<T, E>(signed_pdf: &[u8], timestamp: T) -> Result<Vec<u8>, PadesError>
where
    T: FnOnce(&[u8; 32]) -> Result<chancela_tsa::Timestamp, E>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // Locate the /Contents hex placeholder span.
    let lt =
        pdf::find(signed_pdf, b"/Contents <").ok_or(PadesError::NoSignature)? + b"/Contents ".len(); // '<'
    let hex_start = lt + 1;
    let gt = pdf::find(&signed_pdf[hex_start..], b">")
        .map(|rel| hex_start + rel)
        .ok_or(PadesError::InvalidContents)?;

    // Decode the current CMS from the placeholder hex.
    let cms_der = decode_contents_hex(&signed_pdf[hex_start..gt])?;
    let content_info = ContentInfo::from_der(&cms_der)?;
    let mut signed_data: SignedData = content_info.content.decode_as()?;

    let mut signer_infos: Vec<_> = signed_data.signer_infos.0.iter().cloned().collect();
    let signer = signer_infos
        .first_mut()
        .ok_or(PadesError::InvalidContents)?;

    // Timestamp the SHA-256 of the signature value.
    let sig_digest: [u8; 32] = Sha256::digest(signer.signature.as_bytes()).into();
    let token = timestamp(&sig_digest)
        .map_err(|e| PadesError::Timestamp(e.into()))?
        .token_der;

    // Wrap the token (a ContentInfo) as the id-aa-signatureTimeStampToken unsigned attribute.
    let token_any = Any::from_der(&token)?;
    let attr = Attribute {
        oid: ID_AA_SIGNATURE_TIME_STAMP_TOKEN,
        values: SetOfVec::try_from(vec![token_any])?,
    };
    let unsigned: UnsignedAttributes = SetOfVec::try_from(vec![attr])?;
    signer.unsigned_attrs = Some(unsigned);

    signed_data.signer_infos = SignerInfos(SetOfVec::try_from(signer_infos)?);
    let new_ci = ContentInfo {
        content_type: content_info.content_type,
        content: Any::encode_from(&signed_data)?,
    };
    let new_cms = new_ci.to_der()?;

    // Re-embed into the same placeholder (ByteRange unaffected — /Contents is excluded).
    let capacity = (gt - hex_start) / 2;
    if new_cms.len() > capacity {
        return Err(PadesError::ContentsPlaceholderTooSmall {
            produced: new_cms.len(),
            capacity,
        });
    }
    let mut out = signed_pdf.to_vec();
    for b in &mut out[hex_start..gt] {
        *b = b'0';
    }
    let hex = pdf::to_hex(&new_cms);
    out[hex_start..hex_start + hex.len()].copy_from_slice(&hex);
    Ok(out)
}

/// Decode ASCII-hex `/Contents` bytes into the CMS DER, trimming trailing zero padding to the exact
/// DER object length.
fn decode_contents_hex(hex: &[u8]) -> Result<Vec<u8>, PadesError> {
    let decoded = decode_hex(hex).ok_or(PadesError::InvalidContents)?;
    let len = pdf::der_total_len(&decoded).ok_or(PadesError::InvalidContents)?;
    if len > decoded.len() {
        return Err(PadesError::InvalidContents);
    }
    Ok(decoded[..len].to_vec())
}

/// Decode an even-length ASCII-hex string into bytes (tolerates trailing whitespace).
fn decode_hex(hex: &[u8]) -> Option<Vec<u8>> {
    let trimmed: Vec<u8> = hex
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if trimmed.len() % 2 != 0 {
        return None;
    }
    let val = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.chunks_exact(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}
