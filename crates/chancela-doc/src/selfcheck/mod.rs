//! Structural PDF/A-2u + PDF/UA-1 self-verifier — the invariants we can assert without a native
//! validator.
//!
//! # What this certifies, and over what population
//!
//! This is **not** a general ISO 19005 validator and must never be described as one. It is a
//! validator for *files produced by this writer*, and it earns that narrower claim two ways:
//!
//! * **(A) checks** — rules implemented directly: the cross-reference chain, the XMP identifiers,
//!   the ICC profile's own bytes, `/ToUnicode` correctness glyph by glyph, the tagged-structure
//!   topology, annotation flags.
//! * **(B) invariants** — rules discharged by proving the writer *cannot emit* the construct the
//!   rule constrains. A page whose `/Resources` holds nothing but `/Font`, and whose content stream
//!   draws only from a closed operator list, cannot contain a Separation space, a soft mask, a
//!   transparency group or an inline image, so the entire ISO corpus governing them is vacuous for
//!   this file. Removing a failure mode is stronger than detecting it — but it only holds while the
//!   invariant does, which is why the invariants are asserted on every document rather than assumed.
//!
//! Applied to an arbitrary third-party PDF this module will reject conformant files, because
//! several checks compare against *our* bounded shape (the bundled ICC bytes, the writer's
//! structure roles, the closed operator list). That is the intended trade.
//!
//! # Reach
//!
//! [`verify`] runs inside `pdfa::write` on the bytes it is about to return, so on its own it can
//! only ever see the **pre-signature** document. [`verify_signed`] and [`verify_any`] extend the
//! same rules to a file that `chancela-pades` has appended an incremental update to — the bytes
//! actually shipped — including the signature widget, the `/AcroForm`, any visible seal's
//! appearance stream, and the `/Prev`-chained cross-reference sections that only a signed file has.
//!
//! # Residual gaps
//!
//! Rules neither implemented nor discharged by an invariant, i.e. what an external validator still
//! buys: full ISO 14289 reading-order and alternate-text semantics beyond the writer's bounded
//! topology; `glyf` outline internals (tables are bounds-checked and required, individual glyph
//! programs are not decoded); and XMP schema validation beyond the identifiers and `dc:` fields
//! checked here.
//!
//! PDF/UA-1 is a **separate claim** and is answered separately by [`ua_claim`], not folded into
//! [`verify`]'s pass/fail — see [`UaClaim`] for why.
//!
//! Failures surface as [`DocError::Conformance`].
//!
//! # External verification
//!
//! ```text
//! verapdf --flavour 2u path/to/doc.pdf          # exit 0 == PDF/A-2U conformant
//! verapdf --flavour ua1 path/to/doc.pdf         # exit 0 == PDF/UA-1 conformant
//! verapdf -f 2u --format mrr path/to/doc.pdf    # machine-readable report
//! ```
//!
//! Flavour codes: `2u` = PDF/A-2U, `2a` = 2A, `2b` = 2B, `ua1` = PDF/UA-1. Verify the flag spelling
//! (`--flavour`/`-f`) against the installed veraPDF build; older releases differ.

mod annots;
mod glyphs;
mod icc;
mod render;
mod revisions;

use std::collections::{BTreeMap, BTreeSet};

use lopdf::{Dictionary, Document, Object, ObjectId};

use crate::DocError;

/// Which revision of a Chancela document the bytes under test represent.
///
/// The distinction is structural, not cosmetic: signing appends an incremental update, so a signed
/// file has a `/Prev`-chained second cross-reference section, an `/AcroForm` the unsigned file must
/// not have, and a widget annotation on a page that otherwise carries none. Checking a signed file
/// against the unsigned profile fails on all three; checking an unsigned file against the signed
/// profile lets a missing signature pass unnoticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Bytes exactly as `pdfa::write` returns them: one revision, no annotations, no `/AcroForm`.
    Unsigned,
    /// Bytes after `chancela-pades` appended one or more signature revisions.
    Signed,
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    find_slice(hay, needle).is_some()
}

fn find_slice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn last_startxref(pdf: &[u8]) -> Option<usize> {
    let pos = pdf.windows(9).rposition(|w| w == b"startxref")?;
    let mut i = pos + 9;
    while i < pdf.len() && pdf[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < pdf.len() && pdf[i].is_ascii_digit() {
        i += 1;
    }
    std::str::from_utf8(&pdf[start..i]).ok()?.parse().ok()
}

/// Assert the PDF/A-2u structural invariants on freshly produced, **pre-signature** `bytes`.
///
/// This is the gate `pdfa::write` runs on its own output. For a file that has been signed, use
/// [`verify_signed`]; for bytes of unknown provenance (read back from disk or storage), use
/// [`verify_any`].
pub fn verify(bytes: &[u8]) -> Result<(), DocError> {
    verify_profile(bytes, Profile::Unsigned)
}

/// Assert the same invariants on a file `chancela-pades` has signed.
///
/// Everything [`verify`] checks still applies — the signature is an *incremental update*, so the
/// original revision's bytes survive verbatim underneath it — plus the rules that only have
/// something to bite on once a signature exists: a well-formed `/Prev` chain of classic
/// cross-reference sections, `/ID` carried into the newest trailer, an `/AcroForm` whose fields
/// match the widgets actually attached to pages, and a widget whose flags, `/Rect` and appearance
/// stream satisfy the annotation rules.
///
/// This closes the reach gap: the file Chancela ships is the signed one, and nothing validated it
/// before.
pub fn verify_signed(bytes: &[u8]) -> Result<(), DocError> {
    verify_profile(bytes, Profile::Signed)
}

/// Verify `bytes` under whichever profile they turn out to be, for files read back from disk.
///
/// The discriminator is the catalog's `/AcroForm`: `pdfa::write` never emits one and
/// `chancela-pades` always adds one, so the two populations are disjoint by construction rather
/// than by heuristic.
pub fn verify_any(bytes: &[u8]) -> Result<(), DocError> {
    let signed = Document::load_mem(bytes)
        .ok()
        .and_then(|doc| {
            let root = doc
                .trailer
                .get(b"Root")
                .and_then(Object::as_reference)
                .ok()?;
            Some(doc.get_object(root).ok()?.as_dict().ok()?.has(b"AcroForm"))
        })
        .unwrap_or(false);
    verify_profile(
        bytes,
        if signed {
            Profile::Signed
        } else {
            Profile::Unsigned
        },
    )
}

/// Assert the PDF/A-2u structural invariants on `bytes` under `profile`.
pub fn verify_profile(bytes: &[u8], profile: Profile) -> Result<(), DocError> {
    let fail = |m: String| DocError::Conformance(m);

    // --- Header + binary marker (§2.1) -----------------------------------------------------------
    if !bytes.starts_with(b"%PDF-1.7") {
        return Err(fail("header is not %PDF-1.7".into()));
    }
    // Second line must be a comment with a byte > 127.
    let marker_ok = bytes.get(9..16).is_some_and(|w| w.iter().any(|&b| b > 127));
    if !marker_ok {
        return Err(fail(
            "missing PDF/A binary header marker (byte > 127)".into(),
        ));
    }

    // --- Classic xref table, every revision (C1) -------------------------------------------------
    if !find(bytes, b"\nxref\n") {
        return Err(fail("no classic `xref` table found (xref stream?)".into()));
    }
    verify_revisions(bytes, profile, &fail)?;

    // --- No LZW anywhere (§1.6) ------------------------------------------------------------------
    if find(bytes, b"/LZWDecode") {
        return Err(fail("LZWDecode filter is prohibited in PDF/A".into()));
    }

    // --- Parse for structural checks -------------------------------------------------------------
    let doc = Document::load_mem(bytes)
        .map_err(|e| fail(format!("output does not parse via lopdf: {e}")))?;

    // Trailer: /Root, no /Encrypt. `/ID` is checked against the raw trailer bytes in
    // `verify_revisions` — lopdf merges the revision chain and drops `/ID` when the newest trailer
    // omits it, so `doc.trailer` cannot answer the question for a signed file.
    if doc.trailer.has(b"Encrypt") {
        return Err(fail(
            "trailer carries /Encrypt (encryption is prohibited)".into(),
        ));
    }
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|_| fail("trailer has no /Root reference".into()))?;

    // Catalog.
    let catalog = doc
        .get_object(root_id)
        .and_then(Object::as_dict)
        .map_err(|_| fail("catalog object missing".into()))?;
    match (profile, catalog.has(b"AcroForm")) {
        (Profile::Unsigned, true) => {
            return Err(fail(
                "catalog has /AcroForm (must be absent; pades adds it)".into(),
            ));
        }
        (Profile::Signed, false) => {
            return Err(fail(
                "signed profile: catalog has no /AcroForm, so this file carries no signature"
                    .into(),
            ));
        }
        _ => {}
    }
    if catalog.has(b"AA") {
        return Err(fail(
            "catalog has /AA additional-actions (prohibited)".into(),
        ));
    }
    if !catalog.has(b"Metadata") {
        return Err(fail("catalog has no /Metadata".into()));
    }
    let lang = catalog
        .get(b"Lang")
        .and_then(Object::as_str)
        .map_err(|_| fail("catalog has no textual /Lang".into()))?;
    if lang.is_empty() {
        return Err(fail("catalog /Lang is empty".into()));
    }
    let lang =
        std::str::from_utf8(lang).map_err(|_| fail("catalog /Lang is not valid UTF-8".into()))?;
    verify_document_title_preference(catalog, &fail)?;
    // Collected once and threaded through: the tagged-structure, colour/transparency and glyph
    // checks all reason about the same page content, and re-decoding it per check would let them
    // disagree about what the file says.
    let contents = collect_page_contents(&doc, &fail)?;
    verify_tagged_structure(&doc, catalog, &contents, &fail)?;
    render::verify_pages(&doc, &contents).map_err(fail)?;
    let oi_arr = catalog
        .get(b"OutputIntents")
        .and_then(Object::as_array)
        .map_err(|_| fail("catalog has no /OutputIntents array".into()))?;
    if oi_arr.is_empty() {
        return Err(fail("/OutputIntents is empty".into()));
    }

    // XMP metadata stream: uncompressed, carrying the PDF/A id markers.
    let meta_ref = catalog
        .get(b"Metadata")
        .and_then(Object::as_reference)
        .map_err(|_| fail("/Metadata is not an indirect reference".into()))?;
    let meta = doc
        .get_object(meta_ref)
        .and_then(Object::as_stream)
        .map_err(|_| fail("/Metadata is not a stream".into()))?;
    if meta.dict.has(b"Filter") {
        return Err(fail(
            "/Metadata stream is compressed (must be plaintext, no /Filter)".into(),
        ));
    }
    if !find(&meta.content, b"<pdfaid:part>2</pdfaid:part>") {
        return Err(fail("XMP missing pdfaid:part = 2".into()));
    }
    if !find(&meta.content, b"<pdfaid:conformance>U</pdfaid:conformance>") {
        return Err(fail("XMP missing pdfaid:conformance = U".into()));
    }
    verify_xmp_accessibility_metadata(&meta.content, lang, &fail)?;

    // PDF/UA gate: when the XMP carries the PDF/UA-1 identifier, the file *claims* UA — so it must
    // satisfy the UA invariants this writer can assert, else the claim would be false and we refuse
    // to hand back the bytes. When the identifier is absent the file is a plain PDF/A-2U document
    // (no UA claim) and this gate is a no-op. `/MarkInfo`, `/StructTreeRoot` + non-empty `/RoleMap`,
    // catalog `/Lang`, and `/ViewerPreferences /DisplayDocTitle true` are already enforced above for
    // *every* document, so a UA-claiming file inherently carries them; this adds the UA-specific
    // assertions (identifier + extension schema, heading hierarchy).
    if find(&meta.content, b"pdfuaid:") || find(&meta.content, b"<pdfuaid") {
        verify_pdf_ua_claim(&doc, catalog, &meta.content, &fail)?;
    }

    // OutputIntent: /S GTS_PDFA1 and an N=3 DestOutputProfile.
    let oi_ref = oi_arr[0]
        .as_reference()
        .map_err(|_| fail("OutputIntent is not an indirect reference".into()))?;
    let oi = doc
        .get_object(oi_ref)
        .and_then(Object::as_dict)
        .map_err(|_| fail("OutputIntent object missing".into()))?;
    if oi.get(b"S").and_then(Object::as_name).ok() != Some(b"GTS_PDFA1") {
        return Err(fail("OutputIntent /S is not /GTS_PDFA1".into()));
    }
    let icc_ref = oi
        .get(b"DestOutputProfile")
        .and_then(Object::as_reference)
        .map_err(|_| fail("OutputIntent has no /DestOutputProfile ref".into()))?;
    let icc = doc
        .get_object(icc_ref)
        .and_then(Object::as_stream)
        .map_err(|_| fail("/DestOutputProfile is not a stream".into()))?;
    let declared_n = icc
        .dict
        .get(b"N")
        .and_then(Object::as_i64)
        .map_err(|_| fail("ICC profile stream has no /N component count".into()))?;
    if declared_n != 3 {
        return Err(fail(format!(
            "ICC profile stream /N is {declared_n}, not 3"
        )));
    }
    // The profile's own bytes, not merely its declared component count.
    icc::verify(&icc.content, declared_n).map_err(fail)?;

    // Every font on every page: embedded program + /ToUnicode, then the "u" itself — that the CMap
    // maps every shown glyph, and maps it to what the embedded font agrees it is.
    verify_fonts(&doc, &contents, &fail)?;

    // Annotations. Vacuous before signing; the whole signature surface after.
    match profile {
        Profile::Unsigned => annots::verify_none(&doc).map_err(fail)?,
        Profile::Signed => annots::verify_signature_widgets(&doc, catalog).map_err(fail)?,
    }

    Ok(())
}

/// Whether a file's PDF/UA-1 claim, if it makes one, is one the file actually satisfies.
///
/// PDF/A-2U and PDF/UA-1 are separate conformance claims, and a Chancela document can hold the
/// first without the second. Signing is exactly where they part company: the incremental update
/// leaves every PDF/A property intact but adds a widget annotation, and ISO 14289-1 §7.18.1
/// requires visible annotations to appear in the structure tree. Folding that into [`verify`]'s
/// pass/fail would make a file that *is* archivable look like it is not, and reporting it as a
/// footnote would let a false accessibility claim ship. So it is its own answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UaClaim {
    /// The XMP carries no `pdfuaid` identifier; nothing is claimed and nothing is owed.
    NotClaimed,
    /// The file claims PDF/UA-1 and satisfies the invariants this checker can assert.
    Claimed,
    /// The file claims PDF/UA-1 but demonstrably does not satisfy it.
    Falsified(String),
}

/// Report the PDF/UA-1 claim status of `bytes`.
///
/// See [`UaClaim`]. This runs the annotation-tagging rule that [`verify_signed`] deliberately does
/// not, so a caller can distinguish "not archivable" from "archivable, but claiming an
/// accessibility conformance it lacks" — two problems with different owners and different fixes.
pub fn ua_claim(bytes: &[u8]) -> Result<UaClaim, DocError> {
    let fail = |m: String| DocError::Conformance(m);
    let doc = Document::load_mem(bytes)
        .map_err(|e| fail(format!("input does not parse via lopdf: {e}")))?;
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|_| fail("trailer has no /Root reference".into()))?;
    let catalog = doc
        .get_object(root_id)
        .and_then(Object::as_dict)
        .map_err(|_| fail("catalog object missing".into()))?;
    let meta_ref = catalog
        .get(b"Metadata")
        .and_then(Object::as_reference)
        .map_err(|_| fail("catalog /Metadata is not an indirect reference".into()))?;
    let xmp = doc
        .get_object(meta_ref)
        .and_then(Object::as_stream)
        .map_err(|_| fail("/Metadata is not a stream".into()))?;

    if !find(&xmp.content, b"<pdfuaid:part>1</pdfuaid:part>") {
        return Ok(UaClaim::NotClaimed);
    }
    Ok(match untagged_annotation(&doc) {
        Some(reason) => UaClaim::Falsified(reason),
        None => UaClaim::Claimed,
    })
}

/// Find a visible annotation that is absent from the structure tree, if any.
///
/// A structure element reaches an annotation through an `/OBJR`, and the annotation points back
/// with `/StructParent`; without the latter no `/ParentTree` entry can exist, so the absence of
/// `/StructParent` is sufficient to show the annotation is untagged.
fn untagged_annotation(doc: &Document) -> Option<String> {
    for (page_index, page_id) in doc.page_iter().enumerate() {
        let page = doc.get_object(page_id).and_then(Object::as_dict).ok()?;
        let Ok(Object::Array(annots)) = page.get(b"Annots") else {
            continue;
        };
        for annot in annots {
            let dict = match annot {
                Object::Reference(id) => doc.get_object(*id).and_then(Object::as_dict).ok(),
                Object::Dictionary(dict) => Some(dict),
                _ => None,
            };
            if !dict.is_some_and(|dict| dict.has(b"StructParent")) {
                return Some(format!(
                    "the XMP claims PDF/UA-1, but the page {page_index} signature widget has no \
                     /StructParent and so is absent from the structure tree (ISO 14289-1 7.18.1). \
                     Either tag the widget in the signature revision, or stop claiming PDF/UA-1 \
                     once the file is signed — as it stands the claim is false."
                ));
            }
        }
    }
    None
}

/// Walk the cross-reference chain and assert every revision's shape.
///
/// `/ID` is read here rather than from `lopdf`'s merged trailer for the reason given in
/// [`revisions`]: the merged view silently loses it. ISO 19005-2 §6.1.3 requires the **file
/// trailer dictionary** — the last one — to carry `/ID`, and PDF 32000-1 §7.5.5 requires an
/// incremental update's trailer to repeat the original's first element, which is also what lets a
/// verifier tie the revisions of a signed document together.
fn verify_revisions(
    bytes: &[u8],
    profile: Profile,
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    let revisions = revisions::chain(bytes).map_err(fail)?;

    match (profile, revisions.len()) {
        (Profile::Unsigned, 1) => {}
        (Profile::Unsigned, n) => {
            return Err(fail(format!(
                "unsigned profile: file has {n} cross-reference revisions, expected exactly 1 \
                 (was this file already signed or otherwise appended to?)"
            )));
        }
        (Profile::Signed, 0 | 1) => {
            return Err(fail(
                "signed profile: file has a single cross-reference revision, so no incremental \
                 signature update was ever appended"
                    .into(),
            ));
        }
        (Profile::Signed, _) => {}
    }

    let mut expected_id: Option<(Vec<u8>, Vec<u8>)> = None;
    for (index, revision) in revisions.iter().enumerate() {
        if revision.has_key(b"/Encrypt") {
            return Err(fail(format!(
                "revision at offset {} carries /Encrypt (encryption is prohibited)",
                revision.xref_offset
            )));
        }
        if revision.has_key(b"/XRefStm") {
            return Err(fail(format!(
                "revision at offset {} is a hybrid-reference file (/XRefStm)",
                revision.xref_offset
            )));
        }
        let id = revision.id_pair().ok_or_else(|| {
            fail(format!(
                "revision at offset {} has no well-formed two-element hex /ID in its trailer \
                 (ISO 19005-2 6.1.3 requires it, and an incremental update must repeat it)",
                revision.xref_offset
            ))
        })?;
        if id.0.len() != 16 || id.1 != id.0 {
            return Err(fail(format!(
                "revision at offset {} /ID is not two equal 16-byte strings",
                revision.xref_offset
            )));
        }
        match &expected_id {
            None => expected_id = Some(id),
            Some(first) if first.0 == id.0 => {}
            Some(first) => {
                return Err(fail(format!(
                    "revision {index} /ID[0] {} does not match the newest revision's {}",
                    hex(&id.0),
                    hex(&first.0)
                )));
            }
        }
    }

    Ok(())
}

/// Render bytes as lowercase hex, for `/ID` mismatch diagnostics.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Decode every page's content stream once.
fn collect_page_contents(
    doc: &Document,
    fail: &dyn Fn(String) -> DocError,
) -> Result<Vec<(usize, Vec<u8>)>, DocError> {
    let mut contents = Vec::new();
    for (page_index, page_id) in doc.page_iter().enumerate() {
        let page = doc
            .get_object(page_id)
            .and_then(Object::as_dict)
            .map_err(|_| fail(format!("page {page_index} object missing")))?;
        contents.push((page_index, page_content_bytes(doc, page, page_index, fail)?));
    }
    Ok(contents)
}

fn verify_document_title_preference(
    catalog: &Dictionary,
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    let viewer_preferences = catalog
        .get(b"ViewerPreferences")
        .and_then(Object::as_dict)
        .map_err(|_| fail("catalog has no /ViewerPreferences dictionary".into()))?;
    if !matches!(
        viewer_preferences.get(b"DisplayDocTitle"),
        Ok(Object::Boolean(true))
    ) {
        return Err(fail(
            "catalog /ViewerPreferences does not set /DisplayDocTitle true".into(),
        ));
    }
    Ok(())
}

fn verify_xmp_accessibility_metadata(
    xmp: &[u8],
    catalog_lang: &str,
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    let title_start = b"<rdf:li xml:lang=\"x-default\">";
    let title_end = b"</rdf:li>";
    let title_start_index = find_slice(xmp, title_start)
        .ok_or_else(|| fail("XMP missing dc:title x-default value".into()))?
        + title_start.len();
    let title_end_index = find_slice(&xmp[title_start_index..], title_end)
        .ok_or_else(|| fail("XMP has unterminated dc:title value".into()))?
        + title_start_index;
    if xmp[title_start_index..title_end_index]
        .iter()
        .all(|byte| byte.is_ascii_whitespace())
    {
        return Err(fail("XMP dc:title value is empty".into()));
    }

    if !find(xmp, b"<dc:language>") {
        return Err(fail("XMP missing dc:language".into()));
    }
    let language_entry = format!("<rdf:li>{catalog_lang}</rdf:li>");
    if !find(xmp, language_entry.as_bytes()) {
        return Err(fail(format!(
            "XMP dc:language does not match catalog /Lang {catalog_lang}"
        )));
    }

    Ok(())
}

fn verify_fonts(
    doc: &Document,
    contents: &[(usize, Vec<u8>)],
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    let mut checked_glyphs = false;

    for page_id in doc.page_iter() {
        let fonts = match doc.get_page_fonts(page_id) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for (_name, font) in fonts {
            let subtype = font.get(b"Subtype").and_then(Object::as_name).ok();
            if subtype != Some(b"Type0") {
                return Err(fail(format!(
                    "a page font has /Subtype /{} — the writer emits a single Type0 / Identity-H \
                     composite font, so any simple font came from elsewhere",
                    subtype
                        .map(|s| String::from_utf8_lossy(s).to_string())
                        .unwrap_or_else(|| "(none)".into())
                )));
            }
            let to_unicode_ref = font
                .get(b"ToUnicode")
                .and_then(Object::as_reference)
                .map_err(|_| {
                    fail("a text font has no /ToUnicode CMap (breaks the \"u\")".into())
                })?;
            let to_unicode = doc
                .get_object(to_unicode_ref)
                .and_then(Object::as_stream)
                .map_err(|_| fail("/ToUnicode does not resolve to a stream".into()))?;

            let cid = font
                .get(b"DescendantFonts")
                .and_then(Object::as_array)
                .ok()
                .and_then(|a| a.first())
                .and_then(|first| match first {
                    Object::Reference(r) => doc.get_object(*r).and_then(Object::as_dict).ok(),
                    Object::Dictionary(d) => Some(d),
                    _ => None,
                })
                .ok_or_else(|| fail("Type0 font has no resolvable descendant CIDFont".into()))?;
            let descriptor = cid
                .get(b"FontDescriptor")
                .and_then(Object::as_reference)
                .ok()
                .and_then(|r| doc.get_object(r).and_then(Object::as_dict).ok())
                .ok_or_else(|| fail("a text font has no resolvable /FontDescriptor".into()))?;
            let program_ref = descriptor
                .get(b"FontFile2")
                .and_then(Object::as_reference)
                .map_err(|_| {
                    fail("a text font is not embedded as a /FontFile2 TrueType program".into())
                })?;
            let program = doc
                .get_object(program_ref)
                .and_then(Object::as_stream)
                .map_err(|_| fail("/FontFile2 does not resolve to a stream".into()))?;

            let widths = parse_widths(cid, &fail)?;
            glyphs::verify(
                &program.content,
                program.dict.get(b"Length1").and_then(Object::as_i64).ok(),
                &to_unicode.content,
                &widths,
                contents,
            )
            .map_err(&fail)?;
            checked_glyphs = true;
        }
    }

    if !checked_glyphs {
        return Err(fail(
            "no page declares a font, so no text in this file is extractable".into(),
        ));
    }
    Ok(())
}

/// Parse the CIDFont `/W` array in the `c [w]` form the writer emits, into glyph → width.
///
/// The `c_first c_last w` range form is rejected rather than expanded: the writer never emits it,
/// so encountering one means the widths did not come from this writer and the agreement between
/// `/W` and `hmtx` that [`glyphs::verify`] checks would be asserting the wrong thing.
fn parse_widths(
    cid: &Dictionary,
    fail: &dyn Fn(String) -> DocError,
) -> Result<BTreeMap<u16, i64>, DocError> {
    let array = cid
        .get(b"W")
        .and_then(Object::as_array)
        .map_err(|_| fail("descendant CIDFont has no /W widths array".into()))?;
    let mut widths = BTreeMap::new();
    let mut index = 0usize;

    while index < array.len() {
        let start = array[index]
            .as_i64()
            .map_err(|_| fail("/W entry is not an integer CID".into()))?;
        let list = array
            .get(index + 1)
            .and_then(|entry| entry.as_array().ok())
            .ok_or_else(|| {
                fail(format!(
                    "/W entry for CID {start} is not followed by a width array — the range form \
                     `c_first c_last w` is outside the writer's profile"
                ))
            })?;
        for (offset, width) in list.iter().enumerate() {
            let cid_value = u16::try_from(start + offset as i64)
                .map_err(|_| fail(format!("/W CID {start} is out of range")))?;
            let width = width
                .as_i64()
                .map_err(|_| fail(format!("/W width for CID {cid_value} is not an integer")))?;
            if widths.insert(cid_value, width).is_some() {
                return Err(fail(format!("/W declares CID {cid_value} more than once")));
            }
        }
        index += 2;
    }

    Ok(widths)
}

fn verify_tagged_structure(
    doc: &Document,
    catalog: &Dictionary,
    contents: &[(usize, Vec<u8>)],
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    let mark_info = catalog
        .get(b"MarkInfo")
        .and_then(Object::as_dict)
        .map_err(|_| fail("catalog has no /MarkInfo dictionary".into()))?;
    if !matches!(mark_info.get(b"Marked"), Ok(Object::Boolean(true))) {
        return Err(fail(
            "catalog /MarkInfo does not mark emitted tagged content".into(),
        ));
    }

    let struct_root_ref = catalog
        .get(b"StructTreeRoot")
        .and_then(Object::as_reference)
        .map_err(|_| fail("catalog has no /StructTreeRoot reference".into()))?;
    let struct_root = doc
        .get_object(struct_root_ref)
        .and_then(Object::as_dict)
        .map_err(|_| fail("/StructTreeRoot object missing".into()))?;
    if !struct_root.has_type(b"StructTreeRoot") {
        return Err(fail("/StructTreeRoot has the wrong /Type".into()));
    }

    let role_map = struct_root
        .get(b"RoleMap")
        .and_then(Object::as_dict)
        .map_err(|_| fail("/StructTreeRoot has no /RoleMap dictionary".into()))?;
    if role_map.is_empty() {
        return Err(fail("/StructTreeRoot /RoleMap is empty".into()));
    }
    verify_role_map(role_map, fail)?;

    let parent_tree_ref = struct_root
        .get(b"ParentTree")
        .and_then(Object::as_reference)
        .map_err(|_| fail("/StructTreeRoot has no /ParentTree reference".into()))?;
    let parent_tree = doc
        .get_object(parent_tree_ref)
        .and_then(Object::as_dict)
        .map_err(|_| fail("/ParentTree object missing".into()))?;
    let parent_tree_nums = parent_tree
        .get(b"Nums")
        .and_then(Object::as_array)
        .map_err(|_| fail("/ParentTree has no /Nums array".into()))?;
    let parent_arrays = parse_parent_tree_nums(parent_tree_nums, fail)?;
    let root_k = struct_root
        .get(b"K")
        .map_err(|_| fail("/StructTreeRoot has no /K entry".into()))?;
    verify_local_structure_topology(doc, struct_root_ref, root_k, fail)?;

    let page_ids = doc.page_iter().collect::<Vec<_>>();
    let parent_tree_next_key = struct_root
        .get(b"ParentTreeNextKey")
        .and_then(Object::as_i64)
        .map_err(|_| fail("/StructTreeRoot has no /ParentTreeNextKey integer".into()))?;
    if parent_tree_next_key != page_ids.len() as i64 {
        return Err(fail(format!(
            "/ParentTreeNextKey is {parent_tree_next_key}, expected {}",
            page_ids.len()
        )));
    }

    let page_index_by_id = page_ids
        .iter()
        .enumerate()
        .map(|(index, &id)| (id, index))
        .collect::<BTreeMap<_, _>>();
    let mut page_keys = BTreeSet::new();
    let mut parent_entries = BTreeMap::<(usize, i64), ObjectId>::new();

    for (page_index, &page_id) in page_ids.iter().enumerate() {
        let page = doc
            .get_object(page_id)
            .and_then(Object::as_dict)
            .map_err(|_| fail(format!("page {page_index} object missing")))?;
        let struct_parents = page
            .get(b"StructParents")
            .and_then(Object::as_i64)
            .map_err(|_| fail(format!("page {page_index} has no /StructParents integer")))?;
        if struct_parents != page_index as i64 {
            return Err(fail(format!(
                "page {page_index} /StructParents is {struct_parents}, expected {page_index}"
            )));
        }
        if page.get(b"Tabs").and_then(Object::as_name).ok() != Some(b"S") {
            return Err(fail(format!(
                "page {page_index} /Tabs is not /S structure order"
            )));
        }
        page_keys.insert(struct_parents);

        let parents = parent_arrays.get(&struct_parents).ok_or_else(|| {
            fail(format!(
                "/ParentTree has no array for page {page_index} /StructParents {struct_parents}"
            ))
        })?;
        let content = &contents
            .iter()
            .find(|(index, _)| *index == page_index)
            .ok_or_else(|| fail(format!("page {page_index} content was not collected")))?
            .1;
        verify_marked_content_scopes(content, page_index, fail)?;
        let mcids = content_mcids(content, page_index, fail)?;
        let expected_parent_count = mcids
            .iter()
            .next_back()
            .map(|mcid| (*mcid as usize) + 1)
            .unwrap_or(0);
        if parents.len() != expected_parent_count {
            return Err(fail(format!(
                "page {page_index} /ParentTree array has {} entries, expected {expected_parent_count} from content /MCID values",
                parents.len()
            )));
        }
        for expected_mcid in 0..expected_parent_count {
            let expected_mcid = expected_mcid as i64;
            if !mcids.contains(&expected_mcid) {
                return Err(fail(format!(
                    "page {page_index} /ParentTree has an entry for unused /MCID {expected_mcid}"
                )));
            }
        }
        for (mcid, &element_ref) in parents.iter().enumerate() {
            parent_entries.insert((page_index, mcid as i64), element_ref);
        }
    }

    if parent_arrays.len() != page_keys.len() {
        return Err(fail(format!(
            "/ParentTree has {} page arrays, expected {}",
            parent_arrays.len(),
            page_keys.len()
        )));
    }
    for key in parent_arrays.keys() {
        if !page_keys.contains(key) {
            return Err(fail(format!(
                "/ParentTree has an array for unreferenced StructParents key {key}"
            )));
        }
    }

    let mut mcr_entries = BTreeMap::<(usize, i64), ObjectId>::new();
    let mut seen_struct_elems = BTreeSet::new();
    {
        let mut collector = McrEntryCollector {
            page_index_by_id: &page_index_by_id,
            mcr_entries: &mut mcr_entries,
            seen_struct_elems: &mut seen_struct_elems,
            fail,
            role_map,
        };
        collect_mcr_entries(doc, root_k, None, &mut collector)?;
    }

    for (key, parent_element) in &parent_entries {
        match mcr_entries.get(key) {
            Some(mcr_element) if mcr_element == parent_element => {}
            Some(mcr_element) => {
                return Err(fail(format!(
                    "/ParentTree entry for page {} /MCID {} points to {:?}, but the /MCR is under {:?}",
                    key.0, key.1, parent_element, mcr_element
                )));
            }
            None => {
                return Err(fail(format!(
                    "/ParentTree entry for page {} /MCID {} has no matching structure /MCR",
                    key.0, key.1
                )));
            }
        }
    }
    for key in mcr_entries.keys() {
        if !parent_entries.contains_key(key) {
            return Err(fail(format!(
                "structure /MCR for page {} /MCID {} has no /ParentTree entry",
                key.0, key.1
            )));
        }
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalTopologyRole {
    Document,
    TopLevelBlock,
    Table,
    TableRow,
    TableHeaderCell,
    TableDataCell,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalTopologyParent {
    StructTreeRoot,
    Document,
    Table,
    TableRow,
}

fn verify_local_structure_topology(
    doc: &Document,
    struct_root_ref: ObjectId,
    root_k: &Object,
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    let document_ref = root_k.as_reference().map_err(|_| {
        fail("/StructTreeRoot /K is not the writer document StructElem reference".into())
    })?;
    let mut seen = BTreeSet::new();
    verify_local_topology_element(
        doc,
        document_ref,
        struct_root_ref,
        LocalTopologyParent::StructTreeRoot,
        &mut seen,
        fail,
    )?;
    Ok(())
}

fn verify_local_topology_element(
    doc: &Document,
    elem_ref: ObjectId,
    expected_parent_ref: ObjectId,
    expected_parent: LocalTopologyParent,
    seen: &mut BTreeSet<ObjectId>,
    fail: &dyn Fn(String) -> DocError,
) -> Result<LocalTopologyRole, DocError> {
    if !seen.insert(elem_ref) {
        return Err(fail(format!(
            "tagged table topology repeats StructElem reference {:?}",
            elem_ref
        )));
    }

    let elem = doc
        .get_object(elem_ref)
        .and_then(Object::as_dict)
        .map_err(|_| fail(format!("StructElem {:?} is not a dictionary", elem_ref)))?;
    if !elem.has_type(b"StructElem") {
        return Err(fail(format!("object {:?} is not a /StructElem", elem_ref)));
    }

    let parent_ref = elem
        .get(b"P")
        .and_then(Object::as_reference)
        .map_err(|_| fail("StructElem has no /P parent reference".into()))?;
    if parent_ref != expected_parent_ref {
        return Err(fail(format!(
            "tagged table topology has StructElem {:?} parent {:?}, expected {:?}",
            elem_ref, parent_ref, expected_parent_ref
        )));
    }

    let role_name = elem
        .get(b"S")
        .and_then(Object::as_name)
        .map_err(|_| fail("StructElem has no /S role name".into()))?;
    let role = local_topology_role(role_name).ok_or_else(|| {
        fail(format!(
            "StructElem /{} is outside the writer's bounded tagged-PDF topology",
            String::from_utf8_lossy(role_name)
        ))
    })?;
    if !local_topology_parent_allows(expected_parent, role) {
        return Err(fail(format!(
            "tagged table topology places /{} under {}, expected {}",
            String::from_utf8_lossy(role_name),
            local_topology_parent_label(expected_parent),
            local_topology_expected_child(expected_parent)
        )));
    }

    let kids = elem.get(b"K").and_then(Object::as_array).map_err(|_| {
        fail(format!(
            "StructElem /{} has no writer-profile /K array",
            String::from_utf8_lossy(role_name)
        ))
    })?;

    match role {
        LocalTopologyRole::Document => {
            for kid in kids {
                let child_ref = local_topology_child_ref(kid, role_name, "top-level block", fail)?;
                verify_local_topology_element(
                    doc,
                    child_ref,
                    elem_ref,
                    LocalTopologyParent::Document,
                    seen,
                    fail,
                )?;
            }
        }
        LocalTopologyRole::Table => {
            if kids.is_empty() {
                return Err(fail(format!(
                    "tagged table topology table /{} has no /TR children",
                    String::from_utf8_lossy(role_name)
                )));
            }
            for kid in kids {
                let child_ref = local_topology_child_ref(kid, role_name, "/TR", fail)?;
                verify_local_topology_element(
                    doc,
                    child_ref,
                    elem_ref,
                    LocalTopologyParent::Table,
                    seen,
                    fail,
                )?;
            }
        }
        LocalTopologyRole::TableRow => {
            if kids.is_empty() {
                return Err(fail(
                    "tagged table topology /TR has no /TH or /TD children".into(),
                ));
            }
            let mut header_cell_count = 0usize;
            for kid in kids {
                let child_ref = local_topology_child_ref(kid, role_name, "/TH or /TD", fail)?;
                let child_role = verify_local_topology_element(
                    doc,
                    child_ref,
                    elem_ref,
                    LocalTopologyParent::TableRow,
                    seen,
                    fail,
                )?;
                if child_role == LocalTopologyRole::TableHeaderCell {
                    header_cell_count += 1;
                }
            }
            if header_cell_count == 0 {
                return Err(fail(
                    "tagged table topology /TR has no scoped /TH header cell".into(),
                ));
            }
        }
        LocalTopologyRole::TopLevelBlock => {
            if kids.is_empty() {
                return Err(fail(format!(
                    "tagged table topology leaf /{} has no marked-content references",
                    String::from_utf8_lossy(role_name)
                )));
            }
            for kid in kids {
                verify_local_leaf_kid(kid, role_name, fail)?;
            }
        }
        LocalTopologyRole::TableHeaderCell | LocalTopologyRole::TableDataCell => {
            verify_table_cell_attributes(elem, role_name, fail)?;
            if kids.is_empty() {
                return Err(fail(format!(
                    "tagged table topology leaf /{} has no marked-content references",
                    String::from_utf8_lossy(role_name)
                )));
            }
            for kid in kids {
                verify_local_leaf_kid(kid, role_name, fail)?;
            }
        }
    }

    Ok(role)
}

fn local_topology_role(role: &[u8]) -> Option<LocalTopologyRole> {
    match role {
        b"ChancelaDocument" => Some(LocalTopologyRole::Document),
        b"ChancelaDocumentTitle"
        | b"ChancelaHeaderMetadata"
        | b"ChancelaHeading1"
        | b"ChancelaHeading2"
        | b"ChancelaHeading3"
        | b"ChancelaHeading"
        | b"ChancelaParagraph"
        | b"ChancelaSignatureBlock" => Some(LocalTopologyRole::TopLevelBlock),
        b"ChancelaKeyValue" | b"ChancelaVoteTable" => Some(LocalTopologyRole::Table),
        b"TR" => Some(LocalTopologyRole::TableRow),
        b"TH" => Some(LocalTopologyRole::TableHeaderCell),
        b"TD" => Some(LocalTopologyRole::TableDataCell),
        _ => None,
    }
}

fn local_topology_parent_allows(parent: LocalTopologyParent, child: LocalTopologyRole) -> bool {
    match parent {
        LocalTopologyParent::StructTreeRoot => child == LocalTopologyRole::Document,
        LocalTopologyParent::Document => matches!(
            child,
            LocalTopologyRole::TopLevelBlock | LocalTopologyRole::Table
        ),
        LocalTopologyParent::Table => child == LocalTopologyRole::TableRow,
        LocalTopologyParent::TableRow => matches!(
            child,
            LocalTopologyRole::TableHeaderCell | LocalTopologyRole::TableDataCell
        ),
    }
}

fn local_topology_parent_label(parent: LocalTopologyParent) -> &'static str {
    match parent {
        LocalTopologyParent::StructTreeRoot => "/StructTreeRoot",
        LocalTopologyParent::Document => "/ChancelaDocument",
        LocalTopologyParent::Table => "a table element",
        LocalTopologyParent::TableRow => "/TR",
    }
}

fn local_topology_expected_child(parent: LocalTopologyParent) -> &'static str {
    match parent {
        LocalTopologyParent::StructTreeRoot => "/ChancelaDocument",
        LocalTopologyParent::Document => "a top-level semantic block",
        LocalTopologyParent::Table => "/TR",
        LocalTopologyParent::TableRow => "/TH or /TD",
    }
}

fn local_topology_child_ref(
    kid: &Object,
    role_name: &[u8],
    expected: &str,
    fail: &dyn Fn(String) -> DocError,
) -> Result<ObjectId, DocError> {
    kid.as_reference().map_err(|_| {
        fail(format!(
            "tagged table topology /{} child is not a {expected} StructElem reference",
            String::from_utf8_lossy(role_name)
        ))
    })
}

fn verify_local_leaf_kid(
    kid: &Object,
    role_name: &[u8],
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    if kid.as_reference().is_ok() {
        return Err(fail(format!(
            "tagged table topology leaf /{} contains a nested StructElem reference",
            String::from_utf8_lossy(role_name)
        )));
    }
    let dict = kid.as_dict().map_err(|_| {
        fail(format!(
            "tagged table topology leaf /{} child is not an /MCR dictionary",
            String::from_utf8_lossy(role_name)
        ))
    })?;
    if !dict.has_type(b"MCR") {
        return Err(fail(format!(
            "tagged table topology leaf /{} child is not an /MCR dictionary",
            String::from_utf8_lossy(role_name)
        )));
    }
    Ok(())
}

fn verify_table_cell_attributes(
    elem: &Dictionary,
    role_name: &[u8],
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    if role_name == b"TH" {
        let attrs = elem.get(b"A").and_then(Object::as_dict).map_err(|_| {
            fail("tagged table topology /TH has no table header scope attributes".into())
        })?;
        if attrs.get(b"O").and_then(Object::as_name).ok() != Some(b"Table") {
            return Err(fail(
                "tagged table topology /TH attributes are not owned by /Table".into(),
            ));
        }
        let scope = attrs
            .get(b"Scope")
            .and_then(Object::as_name)
            .map_err(|_| fail("tagged table topology /TH has no /Scope attribute".into()))?;
        if !matches!(scope, b"Row" | b"Column") {
            return Err(fail(format!(
                "tagged table topology /TH has unsupported /Scope /{}",
                String::from_utf8_lossy(scope)
            )));
        }
    } else if let Ok(attrs) = elem.get(b"A").and_then(Object::as_dict)
        && attrs.has(b"Scope")
    {
        return Err(fail(
            "tagged table topology /TD carries a header /Scope attribute".into(),
        ));
    }
    Ok(())
}

fn verify_role_map(
    role_map: &Dictionary,
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    for (custom, mapped) in role_map.iter() {
        if is_standard_structure_role(custom) {
            return Err(fail(format!(
                "/RoleMap redundantly maps standard role /{}",
                String::from_utf8_lossy(custom)
            )));
        }
        let mapped = mapped.as_name().map_err(|_| {
            fail(format!(
                "/RoleMap entry /{} does not map to a name",
                String::from_utf8_lossy(custom)
            ))
        })?;
        if !is_standard_structure_role(mapped) {
            return Err(fail(format!(
                "/RoleMap entry /{} maps to non-standard role /{}",
                String::from_utf8_lossy(custom),
                String::from_utf8_lossy(mapped)
            )));
        }
    }
    Ok(())
}

fn verify_structure_role(
    elem: &Dictionary,
    role_map: &Dictionary,
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    let role = elem
        .get(b"S")
        .and_then(Object::as_name)
        .map_err(|_| fail("StructElem has no /S role name".into()))?;
    if is_standard_structure_role(role) || role_map.has(role) {
        Ok(())
    } else {
        Err(fail(format!(
            "StructElem uses unmapped custom role /{}",
            String::from_utf8_lossy(role)
        )))
    }
}

fn is_standard_structure_role(role: &[u8]) -> bool {
    matches!(
        role,
        b"Document"
            | b"Part"
            | b"Art"
            | b"Sect"
            | b"Div"
            | b"BlockQuote"
            | b"Caption"
            | b"TOC"
            | b"TOCI"
            | b"Index"
            | b"NonStruct"
            | b"Private"
            | b"P"
            | b"H"
            | b"H1"
            | b"H2"
            | b"H3"
            | b"H4"
            | b"H5"
            | b"H6"
            | b"L"
            | b"LI"
            | b"Lbl"
            | b"LBody"
            | b"Table"
            | b"TR"
            | b"TH"
            | b"TD"
            | b"THead"
            | b"TBody"
            | b"TFoot"
            | b"Span"
            | b"Quote"
            | b"Note"
            | b"Reference"
            | b"BibEntry"
            | b"Code"
            | b"Link"
            | b"Annot"
            | b"Ruby"
            | b"RB"
            | b"RT"
            | b"RP"
            | b"Warichu"
            | b"WT"
            | b"WP"
            | b"Figure"
            | b"Formula"
            | b"Form"
    )
}

fn parse_parent_tree_nums(
    nums: &[Object],
    fail: &dyn Fn(String) -> DocError,
) -> Result<BTreeMap<i64, Vec<ObjectId>>, DocError> {
    if !nums.len().is_multiple_of(2) {
        return Err(fail(
            "/ParentTree /Nums must contain key/value pairs".into(),
        ));
    }

    let mut parent_arrays = BTreeMap::new();
    for pair in nums.chunks(2) {
        let key = pair[0]
            .as_i64()
            .map_err(|_| fail("/ParentTree /Nums key is not an integer".into()))?;
        if key < 0 {
            return Err(fail(format!("/ParentTree /Nums key {key} is negative")));
        }
        let values = pair[1].as_array().map_err(|_| {
            fail(format!(
                "/ParentTree /Nums value for key {key} is not an array"
            ))
        })?;
        let mut parents = Vec::with_capacity(values.len());
        for (index, value) in values.iter().enumerate() {
            parents.push(value.as_reference().map_err(|_| {
                fail(format!(
                    "/ParentTree /Nums value for key {key} index {index} is not a structure reference"
                ))
            })?);
        }
        if parent_arrays.insert(key, parents).is_some() {
            return Err(fail(format!(
                "/ParentTree /Nums repeats StructParents key {key}"
            )));
        }
    }

    Ok(parent_arrays)
}

fn page_content_bytes(
    doc: &Document,
    page: &Dictionary,
    page_index: usize,
    fail: &dyn Fn(String) -> DocError,
) -> Result<Vec<u8>, DocError> {
    let contents = page
        .get(b"Contents")
        .map_err(|_| fail(format!("page {page_index} has no /Contents")))?;
    if let Ok(array) = contents.as_array() {
        let mut bytes = Vec::new();
        for item in array {
            bytes.extend_from_slice(&content_stream_bytes(doc, item, page_index, fail)?);
        }
        Ok(bytes)
    } else {
        content_stream_bytes(doc, contents, page_index, fail)
    }
}

fn content_stream_bytes(
    doc: &Document,
    object: &Object,
    page_index: usize,
    fail: &dyn Fn(String) -> DocError,
) -> Result<Vec<u8>, DocError> {
    if let Ok(stream_ref) = object.as_reference() {
        let stream = doc
            .get_object(stream_ref)
            .and_then(Object::as_stream)
            .map_err(|_| {
                fail(format!(
                    "page {page_index} /Contents reference is not a stream"
                ))
            })?;
        Ok(stream.content.clone())
    } else if let Ok(stream) = object.as_stream() {
        Ok(stream.content.clone())
    } else {
        Err(fail(format!(
            "page {page_index} /Contents is neither a stream nor an array of streams"
        )))
    }
}

fn content_mcids(
    content: &[u8],
    page_index: usize,
    fail: &dyn Fn(String) -> DocError,
) -> Result<BTreeSet<i64>, DocError> {
    let mut mcids = BTreeSet::new();
    let mut index = 0;
    while index + b"/MCID".len() <= content.len() {
        if &content[index..index + b"/MCID".len()] != b"/MCID" {
            index += 1;
            continue;
        }

        let mut value_start = index + b"/MCID".len();
        if value_start < content.len() && !is_pdf_whitespace(content[value_start]) {
            index += b"/MCID".len();
            continue;
        }
        while value_start < content.len() && is_pdf_whitespace(content[value_start]) {
            value_start += 1;
        }
        let mut value_end = value_start;
        while value_end < content.len() && content[value_end].is_ascii_digit() {
            value_end += 1;
        }
        if value_start == value_end {
            return Err(fail(format!(
                "page {page_index} marked content has /MCID without a non-negative integer"
            )));
        }
        let mcid = std::str::from_utf8(&content[value_start..value_end])
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(|| fail(format!("page {page_index} has an invalid /MCID value")))?;
        if !mcids.insert(mcid) {
            return Err(fail(format!(
                "page {page_index} repeats marked-content /MCID {mcid}"
            )));
        }
        index = value_end;
    }

    Ok(mcids)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkedScope {
    TaggedContent,
    Artifact,
}

fn verify_marked_content_scopes(
    content: &[u8],
    page_index: usize,
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    let text = String::from_utf8_lossy(content);
    let mut stack = Vec::new();

    for (line_index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.ends_with(" BDC") {
            if line.starts_with("/Artifact ") {
                return Err(fail(format!(
                    "page {page_index} line {} uses /Artifact with BDC instead of BMC",
                    line_index + 1
                )));
            }
            if !line.contains("/MCID ") {
                return Err(fail(format!(
                    "page {page_index} line {} tagged content has no /MCID",
                    line_index + 1
                )));
            }
            stack.push(MarkedScope::TaggedContent);
            continue;
        }
        if line.ends_with(" BMC") {
            if !line.starts_with("/Artifact ") {
                return Err(fail(format!(
                    "page {page_index} line {} uses unrecognised BMC marked content",
                    line_index + 1
                )));
            }
            stack.push(MarkedScope::Artifact);
            continue;
        }
        if line == "EMC" {
            if stack.pop().is_none() {
                return Err(fail(format!(
                    "page {page_index} line {} closes marked content without an open scope",
                    line_index + 1
                )));
            }
            continue;
        }
        if line == "S" && stack.last() != Some(&MarkedScope::Artifact) {
            return Err(fail(format!(
                "page {page_index} paints a path outside an /Artifact marked-content scope"
            )));
        }
        // No untagged real content (UA / G13): every text-showing operator must sit inside a
        // tagged marked-content scope (one carrying an /MCID), never bare or under an /Artifact.
        if is_text_showing_operator(line) && stack.last() != Some(&MarkedScope::TaggedContent) {
            return Err(fail(format!(
                "page {page_index} line {} shows text outside a tagged marked-content scope",
                line_index + 1
            )));
        }
    }

    if !stack.is_empty() {
        return Err(fail(format!(
            "page {page_index} has unclosed marked-content scopes"
        )));
    }

    Ok(())
}

/// A content-stream line whose trailing operator shows text (`Tj`, `TJ`, `'`, `"`).
fn is_text_showing_operator(line: &str) -> bool {
    matches!(
        line.split_whitespace().next_back(),
        Some("Tj") | Some("TJ") | Some("'") | Some("\"")
    )
}

/// Assert the PDF/UA-specific invariants for a file that carries the `pdfuaid` identifier.
///
/// The structural prerequisites (`/MarkInfo`, `/StructTreeRoot` + `/RoleMap`, `/Lang`,
/// `/ViewerPreferences /DisplayDocTitle`) are enforced for every document by [`verify`]; this adds
/// the UA identifier + mandatory `pdfaExtension` schema description and the heading-hierarchy gate.
fn verify_pdf_ua_claim(
    doc: &Document,
    catalog: &Dictionary,
    xmp: &[u8],
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    if !find(xmp, b"<pdfuaid:part>1</pdfuaid:part>") {
        return Err(fail(
            "XMP carries a pdfuaid namespace but not pdfuaid:part = 1".into(),
        ));
    }
    // The `pdfuaid` schema is not predefined, so a PDF/A file must describe it in a pdfaExtension
    // block; without it veraPDF fails both PDF/A and PDF/UA.
    if !find(xmp, b"<pdfaExtension:schemas>")
        || !find(xmp, b"<pdfaSchema:prefix>pdfuaid</pdfaSchema:prefix>")
        || !find(
            xmp,
            b"<pdfaSchema:namespaceURI>http://www.aiim.org/pdfua/ns/id/</pdfaSchema:namespaceURI>",
        )
    {
        return Err(fail(
            "PDF/UA claim is missing the mandatory pdfaExtension schema description for pdfuaid"
                .into(),
        ));
    }
    verify_heading_no_skip(doc, catalog, fail)?;
    Ok(())
}

/// Assert the tagged heading hierarchy does not skip a level (UA / G5), reading heading levels from
/// the structure tree in reading order.
fn verify_heading_no_skip(
    doc: &Document,
    catalog: &Dictionary,
    fail: &dyn Fn(String) -> DocError,
) -> Result<(), DocError> {
    let struct_root_ref = catalog
        .get(b"StructTreeRoot")
        .and_then(Object::as_reference)
        .map_err(|_| fail("catalog has no /StructTreeRoot reference".into()))?;
    let struct_root = doc
        .get_object(struct_root_ref)
        .and_then(Object::as_dict)
        .map_err(|_| fail("/StructTreeRoot object missing".into()))?;
    let root_k = struct_root
        .get(b"K")
        .map_err(|_| fail("/StructTreeRoot has no /K entry".into()))?;

    let mut levels = Vec::new();
    let mut seen = BTreeSet::new();
    collect_heading_levels(doc, root_k, &mut levels, &mut seen);

    let mut previous = 1u8;
    for level in levels {
        if level > previous.saturating_add(1) {
            return Err(fail(format!(
                "PDF/UA heading hierarchy skips a level (H{previous} then H{level})"
            )));
        }
        previous = level;
    }
    Ok(())
}

/// Depth-first, reading-order walk collecting `ChancelaHeading{1,2,3}` levels from the tag tree.
fn collect_heading_levels(
    doc: &Document,
    node: &Object,
    levels: &mut Vec<u8>,
    seen: &mut BTreeSet<ObjectId>,
) {
    match node {
        Object::Reference(id) => {
            if !seen.insert(*id) {
                return;
            }
            let Ok(elem) = doc.get_object(*id).and_then(Object::as_dict) else {
                return;
            };
            if let Ok(role) = elem.get(b"S").and_then(Object::as_name)
                && let Some(level) = heading_level(role)
            {
                levels.push(level);
            }
            if let Ok(kids) = elem.get(b"K") {
                collect_heading_levels(doc, kids, levels, seen);
            }
        }
        Object::Array(items) => {
            for item in items {
                collect_heading_levels(doc, item, levels, seen);
            }
        }
        _ => {}
    }
}

/// Map a heading structure role to its outline level, or `None` for non-heading roles.
fn heading_level(role: &[u8]) -> Option<u8> {
    match role {
        b"ChancelaHeading1" => Some(1),
        b"ChancelaHeading2" => Some(2),
        b"ChancelaHeading3" => Some(3),
        _ => None,
    }
}

fn is_pdf_whitespace(byte: u8) -> bool {
    matches!(byte, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

struct McrEntryCollector<'a> {
    page_index_by_id: &'a BTreeMap<ObjectId, usize>,
    mcr_entries: &'a mut BTreeMap<(usize, i64), ObjectId>,
    seen_struct_elems: &'a mut BTreeSet<ObjectId>,
    fail: &'a dyn Fn(String) -> DocError,
    role_map: &'a Dictionary,
}

fn collect_mcr_entries(
    doc: &Document,
    object: &Object,
    current_element: Option<ObjectId>,
    collector: &mut McrEntryCollector<'_>,
) -> Result<(), DocError> {
    if let Ok(struct_ref) = object.as_reference() {
        if !collector.seen_struct_elems.insert(struct_ref) {
            return Err((collector.fail)(format!(
                "structure tree repeats StructElem reference {:?}",
                struct_ref
            )));
        }
        let elem = doc
            .get_object(struct_ref)
            .and_then(Object::as_dict)
            .map_err(|_| {
                (collector.fail)(format!("StructElem {:?} is not a dictionary", struct_ref))
            })?;
        if !elem.has_type(b"StructElem") {
            return Err((collector.fail)(format!(
                "object {:?} is not a /StructElem",
                struct_ref
            )));
        }
        verify_structure_role(elem, collector.role_map, collector.fail)?;
        if let Ok(kids) = elem.get(b"K") {
            collect_mcr_entries(doc, kids, Some(struct_ref), collector)?;
        }
        return Ok(());
    }

    if let Ok(array) = object.as_array() {
        for item in array {
            collect_mcr_entries(doc, item, current_element, collector)?;
        }
        return Ok(());
    }

    if let Ok(dict) = object.as_dict() {
        if dict.has_type(b"MCR") {
            let element_ref = current_element.ok_or_else(|| {
                (collector.fail)("structure /MCR has no containing /StructElem".into())
            })?;
            let page_ref = dict
                .get(b"Pg")
                .and_then(Object::as_reference)
                .map_err(|_| (collector.fail)("structure /MCR has no /Pg page reference".into()))?;
            let page_index = collector.page_index_by_id.get(&page_ref).ok_or_else(|| {
                (collector.fail)(format!("structure /MCR points to non-page {:?}", page_ref))
            })?;
            let mcid = dict
                .get(b"MCID")
                .and_then(Object::as_i64)
                .map_err(|_| (collector.fail)("structure /MCR has no /MCID integer".into()))?;
            if mcid < 0 {
                return Err((collector.fail)(format!(
                    "structure /MCR has negative /MCID {mcid}"
                )));
            }
            if collector
                .mcr_entries
                .insert((*page_index, mcid), element_ref)
                .is_some()
            {
                return Err((collector.fail)(format!(
                    "structure tree repeats /MCR for page {} /MCID {mcid}",
                    page_index
                )));
            }
            return Ok(());
        }

        return Err((collector.fail)(
            "structure /K dictionary is neither an /MCR nor an indirect /StructElem".into(),
        ));
    }

    Err((collector.fail)(
        "structure /K uses a form outside the writer's bounded tagged-PDF shape".into(),
    ))
}
