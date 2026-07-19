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

use crate::appearance::{self, SealAppearance, SealContent};
use crate::error::PadesError;
use crate::pdf;
use crate::sfnt::Sfnt;
use crate::xmp;

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

/// Resumable state produced by [`prepare_signature`]: the prepared document bytes (ByteRange
/// patched, `/Contents` reserved but still zero-filled), the ByteRange digest an external signer
/// must cover, and the byte span of the hex placeholder needed to embed the CMS later.
///
/// This is the two-phase split of [`sign_pdf`]'s single callback (t57 F5): compute the digest now
/// ([`prepare_signature`]), obtain a detached CMS over it out-of-band (e.g. across an interactive
/// CMD OTP round-trip), then embed it ([`embed_signature`]). All fields are **non-secret** — the
/// prepared PDF, the digest, and a byte offset — so the value is safe to persist between requests
/// (it derives `Serialize`/`Deserialize` for exactly that).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreparedSignature {
    /// The full document bytes, ByteRange already patched, `/Contents` still zero-filled.
    prepared_pdf: Vec<u8>,
    /// SHA-256 over the ByteRange-covered bytes — the digest the detached CMS must cover.
    byterange_digest: [u8; 32],
    /// Index of the first hex character inside `<...>` (one past the `<`).
    hex_start: usize,
}

impl PreparedSignature {
    /// The SHA-256 ByteRange digest the detached CMS must be built over. This is the value the
    /// external signer signs: feed it to `chancela_cades::signed_attributes_digest` (with the
    /// signing certificate and a fixed signing time) to obtain the digest a token/remote signer
    /// actually signs, then `assemble_cades_b` the result before [`embed_signature`].
    pub fn byterange_digest(&self) -> &[u8; 32] {
        &self.byterange_digest
    }

    /// The prepared PDF bytes (incremental update appended, `/ByteRange` final, `/Contents`
    /// reserved but zero-filled). Exposed for inspection; embedding goes through
    /// [`embed_signature`].
    pub fn prepared_pdf(&self) -> &[u8] {
        &self.prepared_pdf
    }
}

/// Sign an existing PDF, producing a PAdES-B-B signature (SIG-21).
///
/// `sign_cms` receives the SHA-256 of the ByteRange-covered bytes and must return a detached CMS
/// (a DER `ContentInfo` wrapping a CAdES-B `SignedData`) over that digest — typically built with
/// `chancela_cades::assemble_cades_b`. The returned bytes are the original PDF plus one incremental
/// update carrying the signature.
///
/// This is the synchronous convenience over the two-phase [`prepare_signature`] →
/// [`embed_signature`] seam: it prepares, invokes the callback, and embeds in one call.
pub fn sign_pdf<S, E>(
    pdf_bytes: &[u8],
    opts: &SignOptions,
    sign_cms: S,
) -> Result<Vec<u8>, PadesError>
where
    S: FnOnce(&[u8; 32]) -> Result<Vec<u8>, E>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    sign_pdf_with_appearance(pdf_bytes, opts, None, sign_cms)
}

/// Sign an existing PDF with an optional **visible seal** appearance (t67-e3).
///
/// Identical to [`sign_pdf`] but, when `appearance` is `Some`, the signature widget gains a real
/// `/Rect` on the requested page and an `/AP /N` appearance stream (a text template or a raster
/// image — see [`SealAppearance`] / [`crate::appearance::SealPlacement`] for the coordinate spec).
/// With `appearance == None` the widget stays the invisible, locked default (`/Rect [0 0 0 0]`, no
/// `/AP`), so existing callers are unaffected.
///
/// The appearance is baked into the prepared bytes, so the `/ByteRange` digest the CMS attests
/// already covers the seal — the two-phase [`prepare_signature_with_appearance`] →
/// [`embed_signature`] seam works the same way.
pub fn sign_pdf_with_appearance<S, E>(
    pdf_bytes: &[u8],
    opts: &SignOptions,
    appearance: Option<&SealAppearance>,
    sign_cms: S,
) -> Result<Vec<u8>, PadesError>
where
    S: FnOnce(&[u8; 32]) -> Result<Vec<u8>, E>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let prepared = prepare_incremental(pdf_bytes, opts, appearance)?;
    let cms = sign_cms(&prepared.byterange_digest).map_err(|e| PadesError::Signer(e.into()))?;
    // No clone: consume the prepared bytes directly (the synchronous path never reuses them).
    embed_cms(prepared.prepared_pdf, prepared.hex_start, &cms)
}

/// **Phase 1 of two-phase signing (t57 F5).** Prepare the incremental-update section over
/// `pdf_bytes` and return the resumable [`PreparedSignature`] — the ByteRange digest to sign plus
/// everything needed to embed the CMS later — **without** yet needing the signature.
///
/// Pair with [`embed_signature`]. `sign_pdf` is this followed immediately by the callback and
/// [`embed_signature`]; splitting them lets a caller suspend between computing the digest and
/// obtaining the CMS (e.g. an interactive OTP round-trip). The same `opts` (notably a fixed
/// `signing_time`) must be used, and the resulting [`PreparedSignature`] carried unchanged into the
/// embed phase.
pub fn prepare_signature(
    pdf_bytes: &[u8],
    opts: &SignOptions,
) -> Result<PreparedSignature, PadesError> {
    prepare_incremental(pdf_bytes, opts, None)
}

/// **Phase 1 of two-phase signing, with an optional visible seal** (t67-e3). Like
/// [`prepare_signature`] but places a [`SealAppearance`] (real `/Rect` + `/AP /N` stream) when
/// `appearance` is `Some`; `None` keeps the invisible, locked default. Pair with
/// [`embed_signature`] exactly as [`prepare_signature`] does — the seal is already in the prepared
/// bytes and covered by the ByteRange digest.
pub fn prepare_signature_with_appearance(
    pdf_bytes: &[u8],
    opts: &SignOptions,
    appearance: Option<&SealAppearance>,
) -> Result<PreparedSignature, PadesError> {
    prepare_incremental(pdf_bytes, opts, appearance)
}

/// **Phase 2 of two-phase signing (t57 F5).** Embed `cms` — a detached CMS built over
/// `prepared.byterange_digest()` — into the reserved `/Contents` placeholder of `prepared`,
/// producing the final signed PDF. The `/ByteRange` is untouched (the placeholder is excluded), so
/// the signature the CMS attests remains valid.
///
/// Borrows `prepared` (cloning its bytes) so the caller may retry embedding or hold the prepared
/// state; the synchronous [`sign_pdf`] path consumes the bytes without a clone.
pub fn embed_signature(prepared: &PreparedSignature, cms: &[u8]) -> Result<Vec<u8>, PadesError> {
    embed_cms(prepared.prepared_pdf.clone(), prepared.hex_start, cms)
}

/// Build the incremental-update section: clone/override the catalog and page, add the AcroForm,
/// signature field, and `/Sig` dictionary, assemble the bytes, patch the `/ByteRange`, and compute
/// the digest over the covered ranges.
fn prepare_incremental(
    pdf_bytes: &[u8],
    opts: &SignOptions,
    appearance: Option<&SealAppearance>,
) -> Result<PreparedSignature, PadesError> {
    if let Some(app) = appearance
        && !(app.placement.w > 0.0 && app.placement.h > 0.0)
    {
        return Err(PadesError::MalformedStructure(
            "seal appearance width and height must be positive".into(),
        ));
    }

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
    // A visible seal targets its requested page; the invisible default stays on the first page
    // (page 0) as before. The signing path assumes a flat page tree (phase-1 input requirement).
    let target_page = appearance.map(|a| a.placement.page).unwrap_or(0);
    let kids = pages
        .get(b"Kids")
        .and_then(lopdf::Object::as_array)
        .map_err(|_| PadesError::MalformedStructure("pages tree has no /Kids".into()))?;
    let page_id = kids
        .get(target_page)
        .and_then(|k| k.as_reference().ok())
        .ok_or_else(|| {
            PadesError::MalformedStructure(format!(
                "requested seal page {target_page} is out of range ({} page(s))",
                kids.len()
            ))
        })?;
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

    // A text seal draws with the document's own embedded font programme (see `appearance::SealFont`
    // for why), so it must be located and parsed before the appearance is built. The programme
    // bytes are held here so the parsed view can borrow them.
    let seal_font_source = match appearance.map(|app| &app.content) {
        Some(SealContent::Text(_)) => Some(seal_font_source(&doc, page_id)?),
        _ => None,
    };
    let seal_font = match &seal_font_source {
        Some(source) => Some(appearance::SealFont {
            program: Sfnt::parse(&source.program)?,
            descriptor: source.descriptor,
            base_font: source.base_font.clone(),
        }),
        None => None,
    };

    // Build the visible-seal appearance objects (form XObject and its font objects, and for image
    // seals the image XObject + optional /SMask), numbered from base + 4. `None` keeps the
    // invisible default.
    let built_appearance = match appearance {
        Some(app) => Some(appearance::build_appearance(
            &app.content,
            app.placement.w,
            app.placement.h,
            base + 4,
            seal_font.as_ref(),
        )?),
        None => None,
    };

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
    // /F 132 = Print (4) + Locked (128). The Invisible/Hidden bits are NOT set, so the widget is
    // displayed and printed; visibility is governed by the `/Rect` and `/AP` below — a zero `/Rect`
    // with no `/AP` shows nothing (the invisible default), a real `/Rect` + `/AP` shows the seal.
    field.set("F", lopdf::Object::Integer(132));
    match (appearance, &built_appearance) {
        (Some(app), Some(built)) => {
            // Real /Rect [x, y, x+w, y+h] on the requested page + the /AP /N appearance stream.
            let p = &app.placement;
            field.set(
                "Rect",
                lopdf::Object::Array(vec![
                    lopdf::Object::Real(p.x),
                    lopdf::Object::Real(p.y),
                    lopdf::Object::Real(p.x + p.w),
                    lopdf::Object::Real(p.y + p.h),
                ]),
            );
            let mut ap = lopdf::Dictionary::new();
            ap.set("N", lopdf::Object::Reference((built.normal_ap_num, 0)));
            field.set("AP", lopdf::Object::Dictionary(ap));
        }
        _ => {
            // Invisible, locked default (backward compatible): zero /Rect, no /AP.
            field.set(
                "Rect",
                lopdf::Object::Array(vec![
                    lopdf::Object::Integer(0),
                    lopdf::Object::Integer(0),
                    lopdf::Object::Integer(0),
                    lopdf::Object::Integer(0),
                ]),
            );
        }
    }
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
    let metadata_override = superseded_metadata(&doc, &catalog)?;

    // Assemble the incremental section, recording each object's absolute offset.
    let prev_len = pdf_bytes.len();
    let mut section: Vec<u8> = Vec::new();
    section.push(b'\n');
    let mut offsets: Vec<(u32, usize)> = Vec::new();

    // The signature dictionary (the only object carrying `/Contents <` and `/ByteRange [0 `) is
    // emitted before any appearance stream so those placeholder searches below cannot mismatch on
    // an image XObject's binary bytes.
    let mut objects: Vec<(u32, Vec<u8>)> = vec![
        (root_id.0, catalog_body),
        (page_id.0, page_body),
        (af_num, acroform_body),
        (field_num, field_body),
        (sig_num, sig_body),
    ];
    if let Some(built) = &built_appearance {
        objects.extend(built.objects.iter().cloned());
    }
    // The superseded XMP goes last, after the signature dictionary, for the same reason the
    // appearance objects do: it carries caller-supplied text (`dc:description`), and a placeholder
    // search below takes the *first* match. The signature dictionary must own that match.
    if let Some(metadata) = &metadata_override {
        objects.push((metadata.id.0, metadata.body.clone()));
    }
    for (id, body) in &objects {
        let off = prev_len + section.len();
        offsets.push((*id, off));
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

    // Trailer + startxref. /Size is one past the highest object number, which the appearance
    // objects may push beyond sig_num.
    let size = objects.iter().map(|(id, _)| *id).max().unwrap_or(sig_num) + 1;
    // Repeat the original /ID. Without it the *file* trailer dictionary of the signed document has
    // no identifier, which ISO 19005-2 6.1.3 requires — so an unsigned PDF/A file would silently
    // stop being one the moment it was signed.
    let id = pdf::trailer_id_array(pdf_bytes)
        .map(|array| format!(" /ID {}", String::from_utf8_lossy(&array)))
        .unwrap_or_default();
    section.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root {} 0 R /Prev {prev_startxref}{id} >>\n",
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

    Ok(PreparedSignature {
        prepared_pdf: bytes,
        byterange_digest: content_digest,
        hex_start,
    })
}

/// Re-emit the document's XMP metadata object without its PDF/UA-1 claim, if it makes one.
///
/// Returns the object id to re-define and its new serialized body, or `None` when the document
/// claims no PDF/UA conformance (so nothing needs superseding). The object keeps **its own number**:
/// redefining it in the incremental update leaves the signed base bytes untouched — which the
/// `/ByteRange` requires — while every reader resolving `/Metadata` reaches the new definition.
///
/// See [`crate::xmp`] for why the claim cannot survive signing.
struct SupersededObject {
    id: (u32, u16),
    body: Vec<u8>,
}

fn superseded_metadata(
    doc: &lopdf::Document,
    catalog: &lopdf::Dictionary,
) -> Result<Option<SupersededObject>, PadesError> {
    let Ok(metadata_id) = catalog
        .get(b"Metadata")
        .and_then(lopdf::Object::as_reference)
    else {
        return Ok(None); // no metadata stream at all: nothing claims anything
    };
    let Ok(stream) = doc
        .get_object(metadata_id)
        .and_then(lopdf::Object::as_stream)
    else {
        return Ok(None);
    };
    let packet = stream
        .decompressed_content()
        .unwrap_or_else(|_| stream.content.clone());
    let Some(stripped) = xmp::without_pdf_ua_claim(&packet)? else {
        return Ok(None);
    };

    // Re-emit uncompressed and without a /Filter: PDF/A requires the document metadata stream to be
    // readable without decoding, and the original was written that way.
    let mut dict = stream.dict.clone();
    dict.remove(b"Filter");
    dict.remove(b"DecodeParms");
    dict.set("Length", lopdf::Object::Integer(stripped.len() as i64));
    let mut body = Vec::with_capacity(stripped.len() + 64);
    pdf::write_dict(&dict, &mut body).map_err(|m| PadesError::MalformedStructure(m.into()))?;
    body.extend_from_slice(b"\nstream\n");
    body.extend_from_slice(&stripped);
    body.extend_from_slice(b"\nendstream");
    Ok(Some(SupersededObject {
        id: metadata_id,
        body,
    }))
}

/// The document's embedded font programme and the objects a seal font reuses from it.
///
/// Held separately from [`appearance::SealFont`] because the parsed view borrows these bytes.
struct SealFontSource {
    program: Vec<u8>,
    descriptor: (u32, u16),
    base_font: Vec<u8>,
}

/// Locate the composite font the sealed page already uses, so a text seal can be drawn with it.
///
/// Failing here is deliberate. The alternative — falling back to a standard-14 face — is what made
/// every visibly-sealed file non-conformant in the first place, and it fails silently. A caller
/// asking for a text seal on a PDF with no embedded TrueType font is asking for something this
/// signer cannot produce conformantly, and is told so.
fn seal_font_source(
    doc: &lopdf::Document,
    page_id: (u32, u16),
) -> Result<SealFontSource, PadesError> {
    let fonts = doc.get_page_fonts(page_id).map_err(|_| {
        PadesError::MalformedStructure(
            "a text seal needs the page's /Resources /Font dictionary, which could not be read"
                .into(),
        )
    })?;

    for font in fonts.values() {
        if font.get(b"Subtype").and_then(lopdf::Object::as_name).ok() != Some(b"Type0") {
            continue;
        }
        let Some(cid) = font
            .get(b"DescendantFonts")
            .and_then(lopdf::Object::as_array)
            .ok()
            .and_then(|array| array.first())
            .and_then(|first| doc.dereference(first).ok())
            .and_then(|(_, object)| object.as_dict().ok())
        else {
            continue;
        };
        let Ok(descriptor_id) = cid
            .get(b"FontDescriptor")
            .and_then(lopdf::Object::as_reference)
        else {
            continue;
        };
        let Ok(descriptor) = doc
            .get_object(descriptor_id)
            .and_then(lopdf::Object::as_dict)
        else {
            continue;
        };
        let Ok(program_id) = descriptor
            .get(b"FontFile2")
            .and_then(lopdf::Object::as_reference)
        else {
            continue;
        };
        let Ok(program) = doc
            .get_object(program_id)
            .and_then(lopdf::Object::as_stream)
        else {
            continue;
        };
        let base_font = cid
            .get(b"BaseFont")
            .and_then(lopdf::Object::as_name)
            .or_else(|_| descriptor.get(b"FontName").and_then(lopdf::Object::as_name))
            .map(<[u8]>::to_vec)
            .unwrap_or_else(|_| b"SealFont".to_vec());
        return Ok(SealFontSource {
            program: program
                .decompressed_content()
                .unwrap_or_else(|_| program.content.clone()),
            descriptor: descriptor_id,
            base_font,
        });
    }

    Err(PadesError::MalformedStructure(
        "a visible text seal must be drawn with an embedded font, but the sealed page declares no \
         Type0 font with a /FontFile2 TrueType programme (a seal drawn with a standard-14 face \
         would make the signed file non-conformant)"
            .into(),
    ))
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
    if !trimmed.len().is_multiple_of(2) {
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
