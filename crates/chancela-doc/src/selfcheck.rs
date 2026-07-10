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

use std::collections::{BTreeMap, BTreeSet};

use lopdf::{Dictionary, Document, Object, ObjectId};

use crate::DocError;

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
    let lang =
        std::str::from_utf8(lang).map_err(|_| fail("catalog /Lang is not valid UTF-8".into()))?;
    verify_document_title_preference(catalog, &fail)?;
    verify_tagged_structure(&doc, catalog, &fail)?;
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
            "XMP claims PDF/UA, but the writer only emits a bounded tagged-PDF structure".into(),
        ));
    }
    verify_xmp_accessibility_metadata(&meta.content, lang, &fail)?;

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

fn verify_tagged_structure(
    doc: &Document,
    catalog: &Dictionary,
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
        let content = page_content_bytes(doc, page, page_index, fail)?;
        verify_marked_content_scopes(&content, page_index, fail)?;
        let mcids = content_mcids(&content, page_index, fail)?;
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
    let root_k = struct_root
        .get(b"K")
        .map_err(|_| fail("/StructTreeRoot has no /K entry".into()))?;
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
    if nums.len() % 2 != 0 {
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
    }

    if !stack.is_empty() {
        return Err(fail(format!(
            "page {page_index} has unclosed marked-content scopes"
        )));
    }

    Ok(())
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
