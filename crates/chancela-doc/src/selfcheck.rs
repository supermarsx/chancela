//! Structural PDF/A-2u self-verifier — the invariants we can assert without a native validator.
//!
//! Run on the writer's own output (§5.1 of the conformance cheatsheet). It mirrors what
//! `chancela-pades` and veraPDF care about: a classic xref table, a binary header marker, `/Root` +
//! `/ID` with no `/Encrypt`, an XMP `/Metadata` stream (uncompressed, carrying the PDF/A markers), a
//! GTS_PDFA1 OutputIntent with an N=3 profile, and every text font embedded with a `/ToUnicode`
//! CMap. Failures surface as [`DocError::Conformance`].
//!
//! # External verification (opt-in, NOT CI-gated)
//!
//! This Rust self-check is the automated gate (no native binary in the distroless ethos). For a
//! full ISO-19005-2 conformance pass, run veraPDF against a generated file out of band:
//!
//! ```text
//! verapdf --flavour 2u path/to/doc.pdf          # exit 0 == PDF/A-2U conformant
//! verapdf -f 2u --format mrr path/to/doc.pdf    # machine-readable report
//! ```
//!
//! Flavour codes: `2u` = PDF/A-2U, `2a` = 2A, `2b` = 2B. Verify the flag spelling
//! (`--flavour`/`-f`) against the installed veraPDF build; older releases differ.

use lopdf::{Document, Object};

use crate::DocError;

fn find(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
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

/// Assert the PDF/A-2u structural invariants on freshly produced `bytes`.
pub fn verify(bytes: &[u8]) -> Result<(), DocError> {
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

    // --- Classic xref table (C1) -----------------------------------------------------------------
    if !find(bytes, b"\nxref\n") {
        return Err(fail("no classic `xref` table found (xref stream?)".into()));
    }
    match last_startxref(bytes) {
        Some(off) if bytes.get(off..off + 4) == Some(b"xref") => {}
        _ => {
            return Err(fail(
                "startxref does not resolve to a classic `xref` table".into(),
            ));
        }
    }

    // --- No LZW anywhere (§1.6) ------------------------------------------------------------------
    if find(bytes, b"/LZWDecode") {
        return Err(fail("LZWDecode filter is prohibited in PDF/A".into()));
    }

    // --- Parse for structural checks -------------------------------------------------------------
    let doc = Document::load_mem(bytes)
        .map_err(|e| fail(format!("output does not parse via lopdf: {e}")))?;

    // Trailer: /Root, /ID (two equal 16-byte strings), no /Encrypt.
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
    match doc.trailer.get(b"ID").and_then(Object::as_array) {
        Ok(a) if a.len() == 2 => {
            let s0 = a[0]
                .as_str()
                .map_err(|_| fail("/ID[0] not a string".into()))?;
            let s1 = a[1]
                .as_str()
                .map_err(|_| fail("/ID[1] not a string".into()))?;
            if s0.len() != 16 || s1 != s0 {
                return Err(fail("/ID must be two equal 16-byte strings".into()));
            }
        }
        _ => return Err(fail("trailer /ID missing or not a 2-element array".into())),
    }

    // Catalog.
    let catalog = doc
        .get_object(root_id)
        .and_then(Object::as_dict)
        .map_err(|_| fail("catalog object missing".into()))?;
    if catalog.has(b"AcroForm") {
        return Err(fail(
            "catalog has /AcroForm (must be absent; pades adds it)".into(),
        ));
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
    if let Ok(mark_info_obj) = catalog.get(b"MarkInfo") {
        let mark_info = mark_info_obj
            .as_dict()
            .map_err(|_| fail("catalog /MarkInfo is not a dictionary".into()))?;
        if matches!(mark_info.get(b"Marked"), Ok(Object::Boolean(true)))
            && !catalog.has(b"StructTreeRoot")
        {
            return Err(fail(
                "catalog claims /MarkInfo /Marked true without /StructTreeRoot".into(),
            ));
        }
    }
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
    if find(&meta.content, b"pdfuaid:") || find(&meta.content, b"<pdfuaid") {
        return Err(fail(
            "XMP claims PDF/UA, but the writer has no tagged-PDF implementation".into(),
        ));
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
    if icc.dict.get(b"N").and_then(Object::as_i64).ok() != Some(3) {
        return Err(fail("ICC profile stream /N is not 3".into()));
    }

    // Every font on every page: embedded program + /ToUnicode.
    verify_fonts(&doc, &fail)?;

    // First page /Annots (C3): absent or inline array.
    if let Some(first_page) = doc.page_iter().next() {
        let page = doc
            .get_object(first_page)
            .and_then(Object::as_dict)
            .map_err(|_| fail("first page object missing".into()))?;
        match page.get(b"Annots") {
            Ok(Object::Array(_)) | Err(_) => {}
            Ok(_) => return Err(fail("first page /Annots is not an inline array".into())),
        }
    }

    Ok(())
}

fn verify_fonts(doc: &Document, fail: &dyn Fn(String) -> DocError) -> Result<(), DocError> {
    for page_id in doc.page_iter() {
        let fonts = match doc.get_page_fonts(page_id) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for (_name, font) in fonts {
            let subtype = font.get(b"Subtype").and_then(Object::as_name).ok();
            if !font.has(b"ToUnicode") {
                return Err(fail(
                    "a text font has no /ToUnicode CMap (breaks the \"u\")".into(),
                ));
            }
            // Locate the FontDescriptor (directly, or via the descendant for Type0).
            let descriptor = if subtype == Some(b"Type0") {
                let desc = font
                    .get(b"DescendantFonts")
                    .and_then(Object::as_array)
                    .ok()
                    .and_then(|a| a.first().cloned());
                let cid = match desc {
                    Some(Object::Reference(r)) => doc.get_object(r).and_then(Object::as_dict).ok(),
                    Some(Object::Dictionary(ref d)) => Some(d),
                    _ => None,
                };
                cid.and_then(|c| c.get(b"FontDescriptor").ok())
                    .and_then(|o| o.as_reference().ok())
                    .and_then(|r| doc.get_object(r).and_then(Object::as_dict).ok())
            } else {
                font.get(b"FontDescriptor")
                    .and_then(Object::as_reference)
                    .ok()
                    .and_then(|r| doc.get_object(r).and_then(Object::as_dict).ok())
            };
            let descriptor = descriptor
                .ok_or_else(|| fail("a text font has no resolvable /FontDescriptor".into()))?;
            let embedded = descriptor.has(b"FontFile2") || descriptor.has(b"FontFile3");
            if !embedded {
                return Err(fail(
                    "a text font is not embedded (no /FontFile2 or /FontFile3)".into(),
                ));
            }
        }
    }
    Ok(())
}
