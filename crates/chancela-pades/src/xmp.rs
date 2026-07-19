//! Dropping the PDF/UA-1 claim from a document's XMP as part of the signature revision.
//!
//! ## Why the claim has to go
//!
//! ISO 14289-1 §7.18.1 requires a visible annotation to be reachable from the structure tree. A
//! PAdES signature widget is not: it is added by an incremental update that has no structure
//! element for it, no `/StructParent`, and no `/ParentTree` entry — and it sets `/F 132` (Print +
//! Locked), so it is not exempt as a hidden annotation either. The PDF/A-2U claim survives signing
//! intact; the PDF/UA-1 claim does not. Leaving `pdfuaid:part` in place after signing asserts an
//! accessibility conformance the signed file demonstrably lacks.
//!
//! The two ways out are to tag the widget or to stop making the claim. This crate takes the second:
//! the signature revision **supersedes** the metadata stream with a copy that carries no PDF/UA
//! identifier. The PDF/A identification, Dublin Core fields and dates are untouched, so a signed
//! file is still PDF/A-2U — it simply no longer claims to be PDF/UA-1.
//!
//! ## Why superseding, not editing
//!
//! The XMP packet lives in the base revision, and the signature's `/ByteRange` covers those bytes.
//! Editing them in place would invalidate the signature it is part of. Instead the incremental
//! update re-emits the metadata object under **the same object number** with the claim removed.
//! The base bytes are untouched, the signature covers the new object as it covers everything else
//! it appends, and any reader resolving `/Metadata` reaches the newest definition — which is
//! exactly what an incremental update is for (PDF 32000-1 §7.5.6).
//!
//! ## The edit itself
//!
//! Three things carry the claim, and all three are removed: the `xmlns:pdfuaid` namespace
//! declaration, the `pdfuaid:part` property, and the `pdfaExtension` schema description that a
//! PDF/A file must supply for the (non-predefined) `pdfuaid` schema. Removing the property but
//! leaving the namespace or the extension block would leave the packet describing a schema nothing
//! uses, which is untidy at best and, for a validator that cross-checks the two, inconsistent.
//! Whole lines are removed so the surrounding packet stays well-formed and readable.

use crate::error::PadesError;

/// Remove the PDF/UA-1 claim from an XMP packet.
///
/// `Ok(None)` means the packet makes no such claim, so the caller can skip superseding the metadata
/// object entirely — signing an already-signed (or never-claiming) document adds nothing. A packet
/// that claims PDF/UA in a shape this cannot fully strip is an **error**, not a silent pass-through:
/// shipping a half-removed claim would be worse than either alternative.
pub(crate) fn without_pdf_ua_claim(packet: &[u8]) -> Result<Option<Vec<u8>>, PadesError> {
    let Ok(text) = std::str::from_utf8(packet) else {
        return Err(PadesError::MalformedStructure(
            "the document's XMP metadata is not valid UTF-8, so its PDF/UA claim cannot be \
             assessed"
                .into(),
        ));
    };
    if !text.contains("pdfuaid") {
        return Ok(None);
    }

    let mut out = text.to_string();
    // The `pdfuaid:part` property and its namespace declaration are one line each.
    remove_line_containing(&mut out, "<pdfuaid:part>");
    remove_line_containing(&mut out, "xmlns:pdfuaid=");
    // The extension schema description is a whole `rdf:Description` element.
    remove_element_containing(&mut out, "<pdfaExtension:schemas>", "rdf:Description");

    if out.contains("pdfuaid") {
        return Err(PadesError::MalformedStructure(
            "the document's XMP claims PDF/UA-1 in a shape this signer cannot drop, and signing \
             would leave the claim standing while the signature widget is untagged (ISO 14289-1 \
             7.18.1)"
                .into(),
        ));
    }
    Ok(Some(out.into_bytes()))
}

/// Delete every line containing `needle`, including its terminating newline.
fn remove_line_containing(text: &mut String, needle: &str) {
    while let Some(at) = text.find(needle) {
        let (start, end) = line_bounds(text, at);
        text.replace_range(start..end, "");
    }
}

/// Delete the whole `<tag …>…</tag>` element that encloses `needle`, line-aligned.
///
/// The opening tag is the last one at or before `needle`; the closing tag is the first one after
/// it. Both are line-aligned before removal so no partial line is left behind.
fn remove_element_containing(text: &mut String, needle: &str, tag: &str) {
    let open_marker = format!("<{tag}");
    let close_marker = format!("</{tag}>");
    while let Some(at) = text.find(needle) {
        let Some(open) = text[..at].rfind(&open_marker) else {
            return;
        };
        let Some(close) = text[at..].find(&close_marker).map(|offset| at + offset) else {
            return;
        };
        let (start, _) = line_bounds(text, open);
        let (_, end) = line_bounds(text, close);
        text.replace_range(start..end, "");
    }
}

/// The byte range of the line containing `at`, from its first byte through its newline (if any).
fn line_bounds(text: &str, at: usize) -> (usize, usize) {
    let start = text[..at].rfind('\n').map(|nl| nl + 1).unwrap_or(0);
    let end = text[at..]
        .find('\n')
        .map(|nl| at + nl + 1)
        .unwrap_or(text.len());
    (start, end)
}
