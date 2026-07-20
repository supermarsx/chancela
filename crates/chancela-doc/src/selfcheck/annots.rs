//! Annotation rules, and the shape a PAdES signature revision is allowed to add.
//!
//! ISO 19005-2 §6.3 constrains annotations: only permitted subtypes, an appearance stream for
//! anything visible, no Hidden/NoView/Invisible flags, Print set, no `/A` actions. Enumerating
//! every subtype's rules is veraPDF's job. Here the population is one annotation kind:
//!
//! * **Unsigned** — `pdfa::write` emits no `/Annots` at all, so the whole annotation corpus is
//!   vacuous. Asserted, not assumed.
//! * **Signed** — `chancela-pades` appends exactly one signature widget per signature. Everything
//!   about it is fixed by the signer, so each rule is checkable against a known-good shape.
//!
//! The visible-seal path matters here. When a seal is requested, the widget gains an `/AP /N` form
//! XObject with its own `/Resources`, which is the one place the signed file can acquire fonts,
//! colour spaces or transparency that never passed through the writer. Those resources are walked
//! with the same closed profile the page content is held to, and a seal font is held to the **same
//! glyph-level rules as a page font** ([`super::glyphs`]): an embedded program, a `/ToUnicode`
//! entry for every glyph shown that round-trips through the font's own `cmap`, and `/W` widths that
//! agree with `hmtx`. Presence checks alone were not enough here — a seal drawn with a standard-14
//! face has no font program at all, and one drawn with an embedded face can still map its glyphs to
//! the wrong characters.

use std::collections::BTreeMap;

use lopdf::{Dictionary, Document, Object};

use super::{glyphs, render};

/// `/F` annotation flag bits (PDF 32000-1 §12.5.3).
const FLAG_INVISIBLE: i64 = 1 << 0;
const FLAG_HIDDEN: i64 = 1 << 1;
const FLAG_PRINT: i64 = 1 << 2;
const FLAG_NO_VIEW: i64 = 1 << 5;

/// Assert no page carries an annotation. Holds for everything `pdfa::write` returns.
pub(super) fn verify_none(doc: &Document) -> Result<(), String> {
    for (page_index, page_id) in doc.page_iter().enumerate() {
        let Ok(page) = doc.get_object(page_id).and_then(Object::as_dict) else {
            continue;
        };
        match page.get(b"Annots") {
            Ok(Object::Array(annots)) if annots.is_empty() => {}
            Err(_) => {}
            Ok(_) => {
                return Err(format!(
                    "page {page_index} carries annotations, but the unsigned writer emits none"
                ));
            }
        }
    }
    Ok(())
}

/// Assert every annotation in a signed file is a conformant signature widget, and that the
/// `/AcroForm` the signature revision added has the shape PDF/A permits.
pub(super) fn verify_signature_widgets(doc: &Document, catalog: &Dictionary) -> Result<(), String> {
    let acroform = catalog
        .get(b"AcroForm")
        .ok()
        .and_then(|object| resolve_dict(doc, object))
        .ok_or("signed file has no resolvable /AcroForm dictionary")?;
    if matches!(acroform.get(b"NeedAppearances"), Ok(Object::Boolean(true))) {
        return Err("/AcroForm sets /NeedAppearances true, which PDF/A prohibits".into());
    }
    let sig_flags = acroform
        .get(b"SigFlags")
        .and_then(Object::as_i64)
        .map_err(|_| "/AcroForm has no /SigFlags integer".to_string())?;
    if sig_flags & 1 == 0 {
        return Err(format!(
            "/AcroForm /SigFlags is {sig_flags}; bit 1 (SignaturesExist) must be set"
        ));
    }
    let fields = acroform
        .get(b"Fields")
        .and_then(Object::as_array)
        .map_err(|_| "/AcroForm has no /Fields array".to_string())?;
    if fields.is_empty() {
        return Err("/AcroForm /Fields is empty in a signed file".into());
    }

    let mut widget_count = 0usize;
    for (page_index, page_id) in doc.page_iter().enumerate() {
        let page = doc
            .get_object(page_id)
            .and_then(Object::as_dict)
            .map_err(|_| format!("page {page_index} object missing"))?;
        let annots = match page.get(b"Annots") {
            Ok(Object::Array(annots)) => annots.clone(),
            Err(_) => continue,
            Ok(_) => {
                return Err(format!("page {page_index} /Annots is not an inline array"));
            }
        };
        for annot in &annots {
            let dict = resolve_dict(doc, annot)
                .ok_or_else(|| format!("page {page_index} has an unresolvable annotation"))?;
            verify_widget(doc, dict, page_index)?;
            widget_count += 1;
            if !fields.iter().any(|field| same_reference(field, annot)) {
                return Err(format!(
                    "page {page_index} widget is not listed in /AcroForm /Fields"
                ));
            }
        }
    }

    if widget_count != fields.len() {
        return Err(format!(
            "/AcroForm /Fields lists {} field(s) but {widget_count} widget annotation(s) are \
             attached to pages",
            fields.len()
        ));
    }
    Ok(())
}

fn verify_widget(doc: &Document, annot: &Dictionary, page_index: usize) -> Result<(), String> {
    let where_ = format!("page {page_index} annotation");

    let subtype = annot
        .get(b"Subtype")
        .and_then(Object::as_name)
        .map_err(|_| format!("{where_} has no /Subtype"))?;
    if subtype != b"Widget" {
        return Err(format!(
            "{where_} has /Subtype /{} — the signer emits signature widgets only, so any other \
             subtype means something else wrote to this file",
            String::from_utf8_lossy(subtype)
        ));
    }
    if annot.get(b"FT").and_then(Object::as_name).ok() != Some(b"Sig") {
        return Err(format!(
            "{where_} is a widget but not a /FT /Sig signature field"
        ));
    }
    if !annot.has(b"V") {
        return Err(format!(
            "{where_} signature field has no /V signature value"
        ));
    }
    if annot.has(b"A") || annot.has(b"AA") {
        return Err(format!(
            "{where_} carries an /A or /AA action, which PDF/A prohibits on annotations"
        ));
    }

    let flags = annot.get(b"F").and_then(Object::as_i64).map_err(|_| {
        format!("{where_} has no /F flags integer (PDF/A requires Print to be set)")
    })?;
    if flags & FLAG_PRINT == 0 {
        return Err(format!("{where_} /F {flags} does not set the Print flag"));
    }
    for (bit, name) in [
        (FLAG_HIDDEN, "Hidden"),
        (FLAG_INVISIBLE, "Invisible"),
        (FLAG_NO_VIEW, "NoView"),
    ] {
        if flags & bit != 0 {
            return Err(format!("{where_} /F {flags} sets the {name} flag"));
        }
    }

    let rect = annot
        .get(b"Rect")
        .and_then(Object::as_array)
        .map_err(|_| format!("{where_} has no /Rect"))?;
    if rect.len() != 4 {
        return Err(format!(
            "{where_} /Rect has {} entries, expected 4",
            rect.len()
        ));
    }
    let numbers: Vec<f64> = rect
        .iter()
        .map(|value| match value {
            Object::Integer(i) => Ok(*i as f64),
            Object::Real(r) => Ok(*r as f64),
            _ => Err(format!("{where_} /Rect has a non-numeric entry")),
        })
        .collect::<Result<_, _>>()?;
    let visible = (numbers[2] - numbers[0]).abs() > 0.0 && (numbers[3] - numbers[1]).abs() > 0.0;

    match annot.get(b"AP").ok().and_then(|ap| resolve_dict(doc, ap)) {
        Some(ap) => {
            let normal = ap
                .get(b"N")
                .map_err(|_| format!("{where_} /AP has no /N normal appearance"))?;
            verify_appearance_stream(doc, normal, &where_)?;
        }
        None if visible => {
            return Err(format!(
                "{where_} has a non-degenerate /Rect but no /AP /N appearance stream"
            ));
        }
        None => {}
    }

    Ok(())
}

/// Walk a widget's normal appearance form XObject under the same closed profile as page content.
fn verify_appearance_stream(doc: &Document, normal: &Object, where_: &str) -> Result<(), String> {
    let stream = match normal {
        Object::Reference(id) => doc
            .get_object(*id)
            .and_then(Object::as_stream)
            .map_err(|_| format!("{where_} /AP /N does not resolve to a stream"))?,
        Object::Stream(stream) => stream,
        _ => return Err(format!("{where_} /AP /N is not a stream")),
    };
    if stream.dict.get(b"Subtype").and_then(Object::as_name).ok() != Some(b"Form") {
        return Err(format!("{where_} /AP /N is not a /Subtype /Form XObject"));
    }
    if !stream.dict.has(b"BBox") {
        return Err(format!("{where_} /AP /N form XObject has no /BBox"));
    }
    if stream.dict.has(b"Group") {
        return Err(format!(
            "{where_} /AP /N declares a /Group transparency group"
        ));
    }

    // The appearance stream is normally Flate-compressed, so every rule below reads the *decoded*
    // operators. Checking the raw bytes would silently pass whatever a compressed stream contains.
    let content = stream
        .decompressed_content()
        .unwrap_or_else(|_| stream.content.clone());

    let Some(resources) = stream
        .dict
        .get(b"Resources")
        .ok()
        .and_then(|object| resolve_dict(doc, object))
    else {
        return Ok(());
    };

    // Fonts inside a seal are the likeliest PDF/A breach in the whole signed file: a seal drawn
    // with a standard-14 face has no font program to embed, and nothing downstream re-validates it.
    if let Some(fonts) = resources
        .get(b"Font")
        .ok()
        .and_then(|object| resolve_dict(doc, object))
    {
        for (name, font) in fonts.iter() {
            let name = String::from_utf8_lossy(name);
            let font = resolve_dict(doc, font)
                .ok_or_else(|| format!("{where_} /AP /N font /{name} does not resolve"))?;
            verify_seal_font(doc, font, &name, &content, where_)?;
        }
    }

    // Everything else the seal declares goes through the page profile: fonts only.
    render::verify_resources(resources, &format!("{where_} /AP /N"))?;
    render::verify_operators(&content, &format!("{where_} /AP /N"))?;
    Ok(())
}

/// Hold one seal font to the full glyph-level profile, not merely to a presence check.
fn verify_seal_font(
    doc: &Document,
    font: &Dictionary,
    name: &str,
    content: &[u8],
    where_: &str,
) -> Result<(), String> {
    let descriptor = font_descriptor(doc, font);
    let embedded = descriptor.is_some_and(|descriptor| {
        descriptor.has(b"FontFile") || descriptor.has(b"FontFile2") || descriptor.has(b"FontFile3")
    });
    if !embedded {
        return Err(format!(
            "{where_} /AP /N font /{name} ({}) has no embedded font program — a visible seal drawn \
             with a non-embedded face makes the signed file non-conformant",
            font.get(b"BaseFont")
                .and_then(Object::as_name)
                .map(|base| String::from_utf8_lossy(base).to_string())
                .unwrap_or_else(|_| "unnamed".into())
        ));
    }
    if !font.has(b"ToUnicode") {
        return Err(format!(
            "{where_} /AP /N font /{name} has no /ToUnicode CMap"
        ));
    }

    // Beyond presence: the same composite-font profile a page font is held to. A simple font would
    // show single-byte codes the glyph reader cannot interpret, so it is rejected outright rather
    // than skipped — skipping would make the seal the one place a font escapes the check.
    if font.get(b"Subtype").and_then(Object::as_name).ok() != Some(b"Type0") {
        return Err(format!(
            "{where_} /AP /N font /{name} is not a Type0 composite font — the seal path emits a \
             single Type0 / Identity-H font, so a simple font came from elsewhere"
        ));
    }
    let to_unicode = font
        .get(b"ToUnicode")
        .and_then(Object::as_reference)
        .ok()
        .and_then(|id| doc.get_object(id).and_then(Object::as_stream).ok())
        .ok_or_else(|| format!("{where_} /AP /N font /{name} /ToUnicode is not a stream"))?;
    let cid = font
        .get(b"DescendantFonts")
        .and_then(Object::as_array)
        .ok()
        .and_then(|array| array.first())
        .and_then(|first| resolve_dict(doc, first))
        .ok_or_else(|| {
            format!("{where_} /AP /N font /{name} has no resolvable descendant CIDFont")
        })?;
    let program = descriptor
        .and_then(|descriptor| {
            descriptor
                .get(b"FontFile2")
                .and_then(Object::as_reference)
                .ok()
        })
        .and_then(|id| doc.get_object(id).and_then(Object::as_stream).ok())
        .ok_or_else(|| {
            format!("{where_} /AP /N font /{name} is not embedded as a /FontFile2 TrueType program")
        })?;

    let mut widths = BTreeMap::new();
    let array = cid
        .get(b"W")
        .and_then(Object::as_array)
        .map_err(|_| format!("{where_} /AP /N font /{name} has no /W widths array"))?;
    let mut index = 0usize;
    while index < array.len() {
        let start = array[index]
            .as_i64()
            .map_err(|_| format!("{where_} /AP /N font /{name} /W entry is not an integer CID"))?;
        let list = array
            .get(index + 1)
            .and_then(|entry| entry.as_array().ok())
            .ok_or_else(|| {
                format!(
                    "{where_} /AP /N font /{name} /W entry for CID {start} is not followed by a \
                     width array — the range form `c_first c_last w` is outside the seal profile"
                )
            })?;
        for (offset, width) in list.iter().enumerate() {
            let cid_value = u16::try_from(start + offset as i64).map_err(|_| {
                format!("{where_} /AP /N font /{name} /W CID {start} is out of range")
            })?;
            let width = width.as_i64().map_err(|_| {
                format!(
                    "{where_} /AP /N font /{name} /W width for CID {cid_value} is not an integer"
                )
            })?;
            if widths.insert(cid_value, width).is_some() {
                return Err(format!(
                    "{where_} /AP /N font /{name} /W declares CID {cid_value} more than once"
                ));
            }
        }
        index += 2;
    }

    let program_bytes = program
        .decompressed_content()
        .unwrap_or_else(|_| program.content.clone());
    let length1 = program
        .dict
        .get(b"Length1")
        .and_then(Object::as_i64)
        .ok()
        // The seal shares the document's /FontFile2, whose /Length1 describes the *stored* stream.
        // A compressed program would make that comparison meaningless, so it is only asserted when
        // the bytes were stored verbatim.
        .filter(|_| !program.dict.has(b"Filter"));
    let subject = format!("{where_} /AP /N seal");
    glyphs::verify(
        &subject,
        &program_bytes,
        length1,
        &to_unicode.content,
        &widths,
        &[(subject.clone(), content)],
    )
    .map_err(|e| format!("{where_} /AP /N font /{name}: {e}"))
}

fn font_descriptor<'a>(doc: &'a Document, font: &'a Dictionary) -> Option<&'a Dictionary> {
    if font.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Type0") {
        let descendant = font
            .get(b"DescendantFonts")
            .and_then(Object::as_array)
            .ok()?;
        let cid = resolve_dict(doc, descendant.first()?)?;
        return resolve_dict(doc, cid.get(b"FontDescriptor").ok()?);
    }
    resolve_dict(doc, font.get(b"FontDescriptor").ok()?)
}

fn resolve_dict<'a>(doc: &'a Document, object: &'a Object) -> Option<&'a Dictionary> {
    match object {
        Object::Reference(id) => doc.get_object(*id).and_then(Object::as_dict).ok(),
        Object::Dictionary(dict) => Some(dict),
        _ => None,
    }
}

fn same_reference(a: &Object, b: &Object) -> bool {
    matches!((a, b), (Object::Reference(x), Object::Reference(y)) if x == y)
}
