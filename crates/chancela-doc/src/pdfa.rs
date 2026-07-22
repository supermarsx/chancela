//! The PDF/A-2u writer: assembles a [`DocumentModel`] into deterministic, PAdES-ready PDF bytes.
//!
//! Object graph (§4 of the conformance cheatsheet): a classic-xref file with a catalog referencing
//! an uncompressed XMP `/Metadata` stream and an sRGB `/OutputIntents` entry, a Type0 / Identity-H /
//! CIDFontType2 font with the whole Noto Serif program embedded as `/FontFile2` plus a `/ToUnicode`
//! CMap, and one content stream per laid-out page. No Info dict, no AcroForm, no encryption — the
//! exact shape `chancela-pades::sign_pdf` appends to.

use std::collections::BTreeMap;

use chancela_core::DocumentModel;
use lopdf::xref::XrefType;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, StringFormat};
use sha2::{Digest, Sha256};

use crate::font::Font;
use crate::{DocError, accessibility, layout, selfcheck, xmp};

pub use crate::accessibility::{
    AccessibilityInput, AccessibilityMetadata, AccessibilityReport, AltTextModel,
    ArtifactMarkingReport, DecorativeArtifact, HeadingHierarchyReport, MarkedContentCoverageReport,
    MetadataValue, NonTextContentReport, PdfUaBlocker, RoleMapCoverageReport, RoleMapEntryReport,
    StructureTreeEvidenceReport, TableSemanticsReport, TextAlternative,
};

/// The bundled sRGB OutputIntent profile (CC0; see `assets/icc/PROVENANCE.md`).
const SRGB_ICC: &[u8] = include_bytes!("../assets/icc/sRGB-v2-micro.icc");

/// PostScript name for the embedded face. No subset prefix: the **whole** program is embedded.
const BASE_FONT: &str = "NotoSerif";

fn name(s: &str) -> Object {
    Object::Name(s.as_bytes().to_vec())
}
fn lit(s: &str) -> Object {
    Object::String(s.as_bytes().to_vec(), StringFormat::Literal)
}

/// Report the accessibility features and PDF/UA blockers the current writer can assert.
pub fn accessibility_report<'a>(input: impl Into<AccessibilityInput<'a>>) -> AccessibilityReport {
    accessibility::report(input)
}

/// The number of pages [`write`] would lay `doc` onto, computed without assembling the PDF.
///
/// Runs the **same** [`layout::lay_out`] pass over the same bundled [`Font`] that [`write`] does,
/// so the count is exactly the page count of the bytes `write` produces. The API reserves a book's
/// page capacity (F14/F15) against this value at the act content-freeze — the one moment the
/// rendered page count is both knowable and permanently stable. Never fewer than one page (an
/// empty document still lays out a single blank page, mirroring [`write`]).
pub fn page_count(doc: &DocumentModel) -> Result<usize, DocError> {
    let font = Font::load()?;
    Ok(layout::lay_out(doc, &font).pages.len())
}

/// Write `doc` as PDF/A-2u bytes and self-verify them before returning.
pub fn write(doc: &DocumentModel) -> Result<Vec<u8>, DocError> {
    let accessibility = accessibility::report(doc);
    let font = Font::load()?;
    let laid = layout::lay_out(doc, &font);

    let mut pdf = Document::with_version("1.7");
    // lopdf 0.43 defaults `new()`/`with_version` to a cross-reference STREAM; PAdES and PDF/A
    // require the classic table, so force it explicitly (resolves cheatsheet [VERIFY] §2.1).
    pdf.reference_table.cross_reference_type = XrefType::CrossReferenceTable;

    // --- Font objects (allocate ids first so page Resources can reference the Type0 font) --------
    let fontfile2_id = pdf.new_object_id();
    let tounicode_id = pdf.new_object_id();
    let descriptor_id = pdf.new_object_id();
    let cidfont_id = pdf.new_object_id();
    let type0_id = pdf.new_object_id();
    let icc_id = pdf.new_object_id();
    let oi_id = pdf.new_object_id();
    let meta_id = pdf.new_object_id();
    let pages_id = pdf.new_object_id();

    // FontFile2: the whole TrueType program, uncompressed (deterministic; /Length1 == /Length).
    let mut ff_dict = Dictionary::new();
    ff_dict.set("Length1", font.data.len() as i64);
    pdf.set_object(
        fontfile2_id,
        Object::Stream(Stream::new(ff_dict, font.data.to_vec())),
    );

    // ToUnicode CMap (mandatory for the "u").
    let mut tu_dict = Dictionary::new();
    let tu = to_unicode_cmap(&laid.used);
    tu_dict.set("Length", tu.len() as i64);
    pdf.set_object(tounicode_id, Object::Stream(Stream::new(tu_dict, tu)));

    // FontDescriptor.
    let mut fd = Dictionary::new();
    fd.set("Type", name("FontDescriptor"));
    fd.set("FontName", name(BASE_FONT));
    fd.set("Flags", Object::Integer(34)); // Serif (2) + Nonsymbolic (32)
    fd.set(
        "FontBBox",
        Object::Array(
            font.bbox
                .iter()
                .map(|&v| Object::Integer(font.scale_1000(v)))
                .collect(),
        ),
    );
    fd.set("ItalicAngle", Object::Integer(font.italic_angle as i64));
    fd.set("Ascent", Object::Integer(font.scale_1000(font.ascent)));
    fd.set("Descent", Object::Integer(font.scale_1000(font.descent)));
    fd.set(
        "CapHeight",
        Object::Integer(font.scale_1000(font.cap_height)),
    );
    fd.set("StemV", Object::Integer(80));
    fd.set("FontFile2", Object::Reference(fontfile2_id));
    pdf.set_object(descriptor_id, Object::Dictionary(fd));

    // CIDFontType2 (descendant).
    let mut cid = Dictionary::new();
    cid.set("Type", name("Font"));
    cid.set("Subtype", name("CIDFontType2"));
    cid.set("BaseFont", name(BASE_FONT));
    let mut csi = Dictionary::new();
    csi.set("Registry", lit("Adobe"));
    csi.set("Ordering", lit("Identity"));
    csi.set("Supplement", Object::Integer(0));
    cid.set("CIDSystemInfo", Object::Dictionary(csi));
    cid.set("FontDescriptor", Object::Reference(descriptor_id));
    cid.set("CIDToGIDMap", name("Identity"));
    cid.set("DW", Object::Integer(500));
    cid.set("W", widths_array(&laid.used, &font));
    pdf.set_object(cidfont_id, Object::Dictionary(cid));

    // Type0 root font.
    let mut t0 = Dictionary::new();
    t0.set("Type", name("Font"));
    t0.set("Subtype", name("Type0"));
    t0.set("BaseFont", name(BASE_FONT));
    t0.set("Encoding", name("Identity-H"));
    t0.set(
        "DescendantFonts",
        Object::Array(vec![Object::Reference(cidfont_id)]),
    );
    t0.set("ToUnicode", Object::Reference(tounicode_id));
    pdf.set_object(type0_id, Object::Dictionary(t0));

    // --- OutputIntent + ICC ----------------------------------------------------------------------
    let mut icc_dict = Dictionary::new();
    icc_dict.set("N", Object::Integer(3));
    pdf.set_object(
        icc_id,
        Object::Stream(Stream::new(icc_dict, SRGB_ICC.to_vec())),
    );

    let mut oi = Dictionary::new();
    oi.set("Type", name("OutputIntent"));
    oi.set("S", name("GTS_PDFA1"));
    oi.set("OutputConditionIdentifier", lit("sRGB IEC61966-2.1"));
    oi.set("Info", lit("sRGB IEC61966-2.1"));
    oi.set("RegistryName", lit("http://www.color.org"));
    oi.set("DestOutputProfile", Object::Reference(icc_id));
    pdf.set_object(oi_id, Object::Dictionary(oi));

    // --- XMP metadata (uncompressed, no /Filter) -------------------------------------------------
    // Emit the PDF/UA-1 identifier only when the document conforms to the writer's UA profile; a
    // non-conforming model stays a plain PDF/A-2U file with no UA claim.
    let xmp_bytes = xmp::packet(doc, &accessibility.metadata, accessibility.pdf_ua_claimed);
    let mut meta_dict = Dictionary::new();
    meta_dict.set("Type", name("Metadata"));
    meta_dict.set("Subtype", name("XML"));
    meta_dict.set("Length", xmp_bytes.len() as i64);
    pdf.set_object(
        meta_id,
        Object::Stream(Stream::new(meta_dict, xmp_bytes.clone())),
    );

    // --- Pages -----------------------------------------------------------------------------------
    let mut page_ids = Vec::with_capacity(laid.pages.len());
    for (page_index, content) in laid.pages.iter().enumerate() {
        let content_id = pdf.new_object_id();
        pdf.set_object(
            content_id,
            Object::Stream(Stream::new(Dictionary::new(), content.clone())),
        );
        let page_id = pdf.new_object_id();

        let mut fonts = Dictionary::new();
        fonts.set("F1", Object::Reference(type0_id));
        let mut resources = Dictionary::new();
        resources.set("Font", Object::Dictionary(fonts));

        let mut page = Dictionary::new();
        page.set("Type", name("Page"));
        page.set("Parent", Object::Reference(pages_id));
        page.set(
            "MediaBox",
            Object::Array(vec![
                Object::Real(0.0),
                Object::Real(0.0),
                Object::Real(595.28),
                Object::Real(841.89),
            ]),
        );
        page.set("Resources", Object::Dictionary(resources));
        page.set("Contents", Object::Reference(content_id));
        page.set("StructParents", Object::Integer(page_index as i64));
        page.set("Tabs", name("S"));
        pdf.set_object(page_id, Object::Dictionary(page));
        page_ids.push(page_id);
    }

    // Pages tree.
    let mut pages = Dictionary::new();
    pages.set("Type", name("Pages"));
    pages.set(
        "Kids",
        Object::Array(page_ids.iter().map(|&id| Object::Reference(id)).collect()),
    );
    pages.set("Count", Object::Integer(page_ids.len() as i64));
    pdf.set_object(pages_id, Object::Dictionary(pages));

    // Tagged PDF structure. This is intentionally minimal and deterministic: one document root,
    // one structure element per semantic layout block/header item, and page-local MCID parent
    // arrays. It supports assistive reading order without making a PDF/UA claim.
    let struct_tree_root_id = emit_structure_tree(
        &mut pdf,
        &laid,
        &page_ids,
        &accessibility.metadata.language.value,
    );

    // Catalog.
    let catalog_id = pdf.new_object_id();
    let mut catalog = Dictionary::new();
    catalog.set("Type", name("Catalog"));
    catalog.set("Pages", Object::Reference(pages_id));
    catalog.set("Metadata", Object::Reference(meta_id));
    catalog.set(
        "OutputIntents",
        Object::Array(vec![Object::Reference(oi_id)]),
    );
    catalog.set("Lang", lit(&accessibility.metadata.language.value));
    catalog.set("StructTreeRoot", Object::Reference(struct_tree_root_id));
    let mut mark_info = Dictionary::new();
    mark_info.set("Marked", Object::Boolean(true));
    catalog.set("MarkInfo", Object::Dictionary(mark_info));
    let mut viewer_preferences = Dictionary::new();
    viewer_preferences.set("DisplayDocTitle", Object::Boolean(true));
    catalog.set("ViewerPreferences", Object::Dictionary(viewer_preferences));
    pdf.set_object(catalog_id, Object::Dictionary(catalog));

    // Trailer: /Root + deterministic /ID (never clock/RNG), no /Encrypt.
    pdf.trailer.set("Root", Object::Reference(catalog_id));
    let id = document_id(&xmp_bytes, &laid.pages);
    let id_obj = Object::String(id.clone(), StringFormat::Hexadecimal);
    pdf.trailer
        .set("ID", Object::Array(vec![id_obj.clone(), id_obj]));

    // Serialize.
    let mut bytes = Vec::new();
    pdf.save_to(&mut bytes).map_err(lopdf::Error::from)?;

    // Structural self-verification before handing the bytes back.
    selfcheck::verify(&bytes)?;
    Ok(bytes)
}

fn emit_structure_tree(
    pdf: &mut Document,
    laid: &layout::Laid,
    page_ids: &[ObjectId],
    language: &str,
) -> ObjectId {
    let root_id = pdf.new_object_id();
    let document_id = pdf.new_object_id();
    let parent_tree_id = pdf.new_object_id();
    let element_ids = laid
        .structure_elements
        .iter()
        .map(|_| pdf.new_object_id())
        .collect::<Vec<_>>();

    for (element_index, (element, &element_id)) in
        laid.structure_elements.iter().zip(&element_ids).enumerate()
    {
        let mut elem = Dictionary::new();
        elem.set("Type", name("StructElem"));
        elem.set("S", name(structure_role_name(element.role)));
        elem.set(
            "P",
            Object::Reference(
                element
                    .parent
                    .map(|parent_index| element_ids[parent_index])
                    .unwrap_or(document_id),
            ),
        );
        elem.set(
            "K",
            Object::Array(structure_element_kids(element, &element_ids, page_ids)),
        );
        if let Some(scope) = table_header_scope(element.role) {
            let mut attrs = Dictionary::new();
            attrs.set("O", name("Table"));
            attrs.set("Scope", name(table_header_scope_name(scope)));
            elem.set("A", Object::Dictionary(attrs));
        }
        debug_assert_eq!(element_ids[element_index], element_id);
        pdf.set_object(element_id, Object::Dictionary(elem));
    }

    let mut document = Dictionary::new();
    document.set("Type", name("StructElem"));
    document.set("S", name("ChancelaDocument"));
    document.set("P", Object::Reference(root_id));
    document.set("Lang", lit(language));
    document.set(
        "K",
        Object::Array(
            laid.structure_elements
                .iter()
                .enumerate()
                .filter(|(_, element)| element.parent.is_none())
                .map(|(index, _)| Object::Reference(element_ids[index]))
                .collect(),
        ),
    );
    pdf.set_object(document_id, Object::Dictionary(document));

    let mut parent_tree = Dictionary::new();
    parent_tree.set(
        "Nums",
        Object::Array(parent_tree_nums(laid, page_ids.len(), &element_ids)),
    );
    pdf.set_object(parent_tree_id, Object::Dictionary(parent_tree));

    let mut root = Dictionary::new();
    root.set("Type", name("StructTreeRoot"));
    root.set("K", Object::Reference(document_id));
    root.set("ParentTree", Object::Reference(parent_tree_id));
    root.set("ParentTreeNextKey", Object::Integer(page_ids.len() as i64));
    root.set("RoleMap", Object::Dictionary(role_map()));
    pdf.set_object(root_id, Object::Dictionary(root));

    root_id
}

fn structure_element_kids(
    element: &layout::TaggedElement,
    element_ids: &[ObjectId],
    page_ids: &[ObjectId],
) -> Vec<Object> {
    let mut kids = Vec::with_capacity(element.children.len() + element.marked_content.len());
    kids.extend(
        element
            .children
            .iter()
            .map(|&child_index| Object::Reference(element_ids[child_index])),
    );
    kids.extend(
        element
            .marked_content
            .iter()
            .map(|marked| marked_content_reference(marked, page_ids)),
    );
    kids
}

fn marked_content_reference(marked: &layout::MarkedContentRef, page_ids: &[ObjectId]) -> Object {
    let mut mcr = Dictionary::new();
    mcr.set("Type", name("MCR"));
    mcr.set("Pg", Object::Reference(page_ids[marked.page_index]));
    mcr.set("MCID", Object::Integer(marked.mcid));
    Object::Dictionary(mcr)
}

fn parent_tree_nums(
    laid: &layout::Laid,
    page_count: usize,
    element_ids: &[ObjectId],
) -> Vec<Object> {
    let mut parents_by_page = vec![Vec::<Option<ObjectId>>::new(); page_count];
    for (element_index, element) in laid.structure_elements.iter().enumerate() {
        for marked in &element.marked_content {
            let page_parents = &mut parents_by_page[marked.page_index];
            let mcid = marked.mcid as usize;
            if page_parents.len() <= mcid {
                page_parents.resize(mcid + 1, None);
            }
            page_parents[mcid] = Some(element_ids[element_index]);
        }
    }

    let mut nums = Vec::with_capacity(page_count * 2);
    for (page_index, page_parents) in parents_by_page.iter().enumerate() {
        nums.push(Object::Integer(page_index as i64));
        nums.push(Object::Array(
            page_parents
                .iter()
                .map(|parent| Object::Reference(parent.expect("every emitted MCID has a parent")))
                .collect(),
        ));
    }
    nums
}

fn structure_role_name(role: layout::StructureRole) -> &'static str {
    match role {
        layout::StructureRole::DocumentTitle => "ChancelaDocumentTitle",
        layout::StructureRole::HeaderMetadata => "ChancelaHeaderMetadata",
        layout::StructureRole::Heading(1) => "ChancelaHeading1",
        layout::StructureRole::Heading(2) => "ChancelaHeading2",
        layout::StructureRole::Heading(3) => "ChancelaHeading3",
        layout::StructureRole::Heading(_) => "ChancelaHeading",
        layout::StructureRole::Paragraph => "ChancelaParagraph",
        layout::StructureRole::KeyValueTable => "ChancelaKeyValue",
        layout::StructureRole::VoteTable => "ChancelaVoteTable",
        layout::StructureRole::TableRow => "TR",
        layout::StructureRole::TableHeaderCell(_) => "TH",
        layout::StructureRole::TableDataCell => "TD",
        layout::StructureRole::SignatureBlock => "ChancelaSignatureBlock",
    }
}

fn table_header_scope(role: layout::StructureRole) -> Option<layout::TableHeaderScope> {
    match role {
        layout::StructureRole::TableHeaderCell(scope) => Some(scope),
        _ => None,
    }
}

fn table_header_scope_name(scope: layout::TableHeaderScope) -> &'static str {
    match scope {
        layout::TableHeaderScope::Row => "Row",
        layout::TableHeaderScope::Column => "Column",
    }
}

fn role_map() -> Dictionary {
    let mut roles = Dictionary::new();
    for &(custom, standard) in accessibility::role_map_entries() {
        roles.set(custom, name(standard));
    }
    roles
}

/// Derive a 16-byte document `/ID` deterministically from the content (XMP + page streams), never a
/// clock or RNG — so the same [`DocumentModel`] reproduces byte-identical output and `pdf_digest`.
fn document_id(xmp_bytes: &[u8], pages: &[Vec<u8>]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update((xmp_bytes.len() as u64).to_be_bytes());
    h.update(xmp_bytes);
    for p in pages {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize()[..16].to_vec()
}

/// Build the `/W` widths array for the used CIDs (== glyph ids under Identity-H).
fn widths_array(used: &BTreeMap<u16, u32>, font: &Font) -> Object {
    let mut arr = Vec::new();
    for &gid in used.keys() {
        arr.push(Object::Integer(gid as i64));
        arr.push(Object::Array(vec![Object::Integer(
            font.glyph_width_1000(gid),
        )]));
    }
    Object::Array(arr)
}

/// Build the `/ToUnicode` CMap mapping each used CID (glyph id) to its Unicode scalar(s).
fn to_unicode_cmap(used: &BTreeMap<u16, u32>) -> Vec<u8> {
    let mut body = String::new();
    body.push_str(
        "/CIDInit /ProcSet findresource begin\n\
12 dict begin\n\
begincmap\n\
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
/CMapName /Adobe-Identity-UCS def\n\
/CMapType 2 def\n\
1 begincodespacerange\n\
<0000> <FFFF>\n\
endcodespacerange\n",
    );
    let entries: Vec<(u16, u32)> = used.iter().map(|(&g, &u)| (g, u)).collect();
    for chunk in entries.chunks(100) {
        body.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for &(gid, scalar) in chunk {
            body.push_str(&format!("<{:04X}> <{}>\n", gid, utf16be_hex(scalar)));
        }
        body.push_str("endbfchar\n");
    }
    body.push_str(
        "endcmap\n\
CMapName currentdict /CMap defineresource pop\n\
end\n\
end",
    );
    body.into_bytes()
}

/// Encode a Unicode scalar as big-endian UTF-16 hex (surrogate pair when outside the BMP).
fn utf16be_hex(scalar: u32) -> String {
    if let Some(c) = char::from_u32(scalar) {
        let mut buf = [0u16; 2];
        let units = c.encode_utf16(&mut buf);
        units.iter().map(|u| format!("{u:04X}")).collect()
    } else {
        "FFFD".to_string()
    }
}
