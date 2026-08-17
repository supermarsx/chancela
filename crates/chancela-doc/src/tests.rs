//! Unit tests for the PDF/A-2u writer (structural self-check, determinism, pagination, and the
//! diacritic `/ToUnicode` round-trip). The generate→pades-sign round-trip lives in `tests/` and is
//! owned by e3.
//!
//! Fixtures use the fictional "Encosto Estratégico Lda" / "Amélia Marques" — never a real entity.

use chancela_core::{
    Block, DocumentFontFamily, DocumentLayoutPolicy, DocumentModel, DocumentOrientation,
    DocumentPageSize, DocumentSideTextEdge, KvRow, Run, SignatureSlot, VoteRow,
};
use lopdf::{Dictionary, Document, Object, ObjectId};

use crate::{font::Font, pdfa, selfcheck};

/// A representative CSC general-meeting ata exercising every block type, with pt-PT diacritics.
fn fixture() -> DocumentModel {
    let mut doc = DocumentModel::new(
        "Ata da Assembleia Geral",
        "Encosto Estratégico Lda",
        "Deliberação sobre contas e distribuição de resultados",
    );
    doc.entity_nipc = Some("500123456".to_string());
    doc.created_at = Some("2026-07-06T10:30:00Z".to_string());
    doc.blocks = vec![
        Block::Heading {
            level: 1,
            text: "Ata número três".to_string(),
        },
        Block::Paragraph {
            runs: vec![
                Run {
                    text: "Aos seis dias do mês de julho reuniu a assembleia geral da sociedade, \
                           com a presença de "
                        .to_string(),
                    bold: false,
                    italic: false,
                },
                Run {
                    text: "todos os sócios".to_string(),
                    bold: true,
                    italic: false,
                },
                Run {
                    text: ", para deliberação dos pontos da ordem de trabalhos. A reunião \
                           decorreu na sede social, sita na Rua das Oliveiras."
                        .to_string(),
                    bold: false,
                    italic: true,
                },
            ],
        },
        Block::KeyValue {
            rows: vec![
                KvRow {
                    key: "Presidente da mesa".to_string(),
                    value: "Amélia Marques".to_string(),
                },
                KvRow {
                    key: "Data".to_string(),
                    value: "6 de julho de 2026".to_string(),
                },
            ],
        },
        Block::Heading {
            level: 2,
            text: "Votação".to_string(),
        },
        Block::VoteTable {
            rows: vec![
                VoteRow {
                    label: "Aprovação das contas".to_string(),
                    favor: 3,
                    against: 0,
                    abstain: 1,
                },
                VoteRow {
                    label: "Distribuição de resultados".to_string(),
                    favor: 4,
                    against: 0,
                    abstain: 0,
                },
            ],
        },
        Block::Rule,
        Block::SignatureBlock {
            slots: vec![
                SignatureSlot {
                    role: "Presidente da mesa".to_string(),
                    name: "Amélia Marques".to_string(),
                },
                SignatureSlot {
                    role: "Secretário".to_string(),
                    name: "João Nogueira".to_string(),
                },
            ],
        },
    ];
    doc
}

fn catalog(parsed: &Document) -> &Dictionary {
    let root = parsed
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .unwrap();
    parsed.get_object(root).and_then(Object::as_dict).unwrap()
}

fn xmp_text(parsed: &Document) -> String {
    let catalog = catalog(parsed);
    let meta_ref = catalog
        .get(b"Metadata")
        .and_then(Object::as_reference)
        .unwrap();
    let meta = parsed
        .get_object(meta_ref)
        .and_then(Object::as_stream)
        .unwrap();
    String::from_utf8_lossy(&meta.content).into_owned()
}

fn content_stream_text(parsed: &Document) -> String {
    let mut bytes = Vec::new();
    for page_id in parsed.page_iter() {
        let page = parsed
            .get_object(page_id)
            .and_then(Object::as_dict)
            .unwrap();
        let content_ref = page
            .get(b"Contents")
            .and_then(Object::as_reference)
            .unwrap();
        let content = parsed
            .get_object(content_ref)
            .and_then(Object::as_stream)
            .unwrap();
        bytes.extend_from_slice(&content.content);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn first_page(parsed: &Document) -> &Dictionary {
    let page_id = parsed.page_iter().next().expect("first page");
    parsed
        .get_object(page_id)
        .and_then(Object::as_dict)
        .expect("first page dictionary")
}

fn number(object: &Object) -> f32 {
    match object {
        Object::Real(value) => *value,
        Object::Integer(value) => *value as f32,
        other => panic!("expected PDF number, got {other:?}"),
    }
}

fn media_box(parsed: &Document) -> [f32; 4] {
    let values = first_page(parsed)
        .get(b"MediaBox")
        .and_then(Object::as_array)
        .expect("page MediaBox");
    [
        number(&values[0]),
        number(&values[1]),
        number(&values[2]),
        number(&values[3]),
    ]
}

fn content_text_fragments(parsed: &Document) -> Vec<String> {
    content_stream_text(parsed)
        .lines()
        .filter_map(|line| {
            line.strip_prefix('<')
                .and_then(|line| line.strip_suffix("> Tj"))
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn glyph_hex(font: &Font, text: &str) -> String {
    text.chars()
        .map(|ch| format!("{:04X}", font.glyph_id(ch)))
        .collect()
}

fn assert_text_fragment_sequence(parsed: &Document, expected: &[String]) {
    let fragments = content_text_fragments(parsed);
    assert!(
        fragments
            .windows(expected.len())
            .any(|window| window == expected),
        "missing text fragment sequence {expected:?} in {fragments:?}"
    );
}

fn assert_tounicode_maps_space(parsed: &Document, font: &Font) {
    let space_gid = font.glyph_id(' ');
    let expected = format!("<{space_gid:04X}> <0020>");
    let cmap = parsed
        .objects
        .values()
        .filter_map(|o| o.as_stream().ok())
        .find(|s| s.content.windows(11).any(|w| w == b"beginbfchar"))
        .expect("a /ToUnicode bfchar CMap stream");
    let text = String::from_utf8_lossy(&cmap.content);
    assert!(
        text.contains(&expected),
        "ToUnicode CMap is missing U+0020 mapping {expected}"
    );
}

fn collect_structure_roles(parsed: &Document, elem_ref: ObjectId, out: &mut Vec<Vec<u8>>) {
    let elem = parsed
        .get_object(elem_ref)
        .and_then(Object::as_dict)
        .expect("StructElem dict");
    if let Ok(role) = elem.get(b"S").and_then(Object::as_name) {
        out.push(role.to_vec());
    }
    if let Ok(kids) = elem.get(b"K") {
        collect_structure_kids(parsed, kids, out);
    }
}

fn collect_structure_kids(parsed: &Document, kid: &Object, out: &mut Vec<Vec<u8>>) {
    match kid {
        Object::Reference(id) => collect_structure_roles(parsed, *id, out),
        Object::Array(items) => {
            for item in items {
                collect_structure_kids(parsed, item, out);
            }
        }
        _ => {}
    }
}

fn collect_table_header_scopes(parsed: &Document, elem_ref: ObjectId, out: &mut Vec<Vec<u8>>) {
    let elem = parsed
        .get_object(elem_ref)
        .and_then(Object::as_dict)
        .expect("StructElem dict");
    if elem.get(b"S").and_then(Object::as_name).ok() == Some(b"TH".as_slice()) {
        let attrs = elem
            .get(b"A")
            .and_then(Object::as_dict)
            .expect("TH table attributes");
        assert_eq!(
            attrs
                .get(b"O")
                .and_then(Object::as_name)
                .expect("TH attribute owner"),
            b"Table"
        );
        out.push(
            attrs
                .get(b"Scope")
                .and_then(Object::as_name)
                .expect("TH scope")
                .to_vec(),
        );
    }
    if let Ok(kids) = elem.get(b"K") {
        collect_table_header_scope_kids(parsed, kids, out);
    }
}

fn collect_table_header_scope_kids(parsed: &Document, kid: &Object, out: &mut Vec<Vec<u8>>) {
    match kid {
        Object::Reference(id) => collect_table_header_scopes(parsed, *id, out),
        Object::Array(items) => {
            for item in items {
                collect_table_header_scope_kids(parsed, item, out);
            }
        }
        _ => {}
    }
}

fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len(), "replacement must preserve offsets");
    let pos = bytes
        .windows(from.len())
        .position(|w| w == from)
        .unwrap_or_else(|| panic!("missing byte pattern: {}", String::from_utf8_lossy(from)));
    bytes[pos..pos + from.len()].copy_from_slice(to);
}

#[test]
fn fixture_writes_and_self_checks() {
    let bytes = pdfa::write(&fixture()).expect("write PDF/A");
    // The writer runs the self-check internally; assert the output parses and re-verify shape.
    let parsed = Document::load_mem(&bytes).expect("output parses via lopdf");
    assert_eq!(parsed.version, "1.7");
    assert!(bytes.starts_with(b"%PDF-1.7"));
    // Binary header marker (byte > 127 on the second line).
    assert!(bytes[9..16].iter().any(|&b| b > 127));
    // Classic xref table, not a stream.
    assert!(bytes.windows(6).any(|w| w == b"\nxref\n"));
    // pades shape: no AcroForm, /Root + /ID present, no /Encrypt.
    assert!(!bytes.windows(9).any(|w| w == b"/AcroForm"));
    assert!(parsed.trailer.has(b"Root"));
    assert!(parsed.trailer.has(b"ID"));
    assert!(!parsed.trailer.has(b"Encrypt"));
}

#[test]
fn tagged_pdf_structure_markers_are_emitted() {
    let bytes = pdfa::write(&fixture()).expect("write");
    assert!(bytes.windows(15).any(|w| w == b"/StructTreeRoot"));
    assert!(bytes.windows(8).any(|w| w == b"/RoleMap"));
    assert!(bytes.windows(11).any(|w| w == b"/ParentTree"));

    let parsed = Document::load_mem(&bytes).expect("parse");
    let catalog = catalog(&parsed);
    let mark_info = catalog
        .get(b"MarkInfo")
        .and_then(Object::as_dict)
        .expect("MarkInfo dictionary");
    assert!(matches!(
        mark_info.get(b"Marked"),
        Ok(Object::Boolean(true))
    ));
    let viewer_preferences = catalog
        .get(b"ViewerPreferences")
        .and_then(Object::as_dict)
        .expect("ViewerPreferences dictionary");
    assert!(matches!(
        viewer_preferences.get(b"DisplayDocTitle"),
        Ok(Object::Boolean(true))
    ));

    let struct_root_ref = catalog
        .get(b"StructTreeRoot")
        .and_then(Object::as_reference)
        .expect("StructTreeRoot ref");
    let struct_root = parsed
        .get_object(struct_root_ref)
        .and_then(Object::as_dict)
        .expect("StructTreeRoot dict");
    let role_map = struct_root
        .get(b"RoleMap")
        .and_then(Object::as_dict)
        .expect("RoleMap dict");
    assert!(role_map.has(b"ChancelaDocument"));
    assert!(role_map.has(b"ChancelaDocumentTitle"));
    assert!(role_map.has(b"ChancelaParagraph"));
    assert_eq!(
        role_map
            .get(b"ChancelaKeyValue")
            .and_then(Object::as_name)
            .expect("key/value role map target"),
        b"Table"
    );
    assert_eq!(
        role_map
            .get(b"ChancelaVoteTable")
            .and_then(Object::as_name)
            .expect("vote-table role map target"),
        b"Table"
    );
    assert!(role_map.has(b"ChancelaVoteTable"));

    let document_ref = struct_root
        .get(b"K")
        .and_then(Object::as_reference)
        .expect("document StructElem ref");
    let document = parsed
        .get_object(document_ref)
        .and_then(Object::as_dict)
        .expect("document StructElem");
    assert_eq!(
        document.get(b"S").and_then(Object::as_name).unwrap(),
        b"ChancelaDocument"
    );
    assert_eq!(
        document.get(b"Lang").and_then(Object::as_str).unwrap(),
        b"pt-PT"
    );
    let mut roles = Vec::new();
    collect_structure_roles(&parsed, document_ref, &mut roles);
    for expected in [
        b"ChancelaKeyValue".as_slice(),
        b"ChancelaVoteTable".as_slice(),
        b"TR".as_slice(),
        b"TH".as_slice(),
        b"TD".as_slice(),
    ] {
        assert!(
            roles.iter().any(|role| role.as_slice() == expected),
            "missing structure role {} in {:?}",
            String::from_utf8_lossy(expected),
            roles
                .iter()
                .map(|role| String::from_utf8_lossy(role).into_owned())
                .collect::<Vec<_>>()
        );
    }
    let mut header_scopes = Vec::new();
    collect_table_header_scopes(&parsed, document_ref, &mut header_scopes);
    assert_eq!(
        header_scopes
            .iter()
            .filter(|scope| scope.as_slice() == b"Row")
            .count(),
        4,
        "key/value keys and vote labels must be scoped row headers"
    );
    assert_eq!(
        header_scopes
            .iter()
            .filter(|scope| scope.as_slice() == b"Column")
            .count(),
        4,
        "vote table header row must be scoped column headers"
    );

    let parent_tree_ref = struct_root
        .get(b"ParentTree")
        .and_then(Object::as_reference)
        .expect("ParentTree ref");
    let parent_tree = parsed
        .get_object(parent_tree_ref)
        .and_then(Object::as_dict)
        .expect("ParentTree dict");
    let nums = parent_tree
        .get(b"Nums")
        .and_then(Object::as_array)
        .expect("ParentTree nums");
    assert!(!nums.is_empty(), "parent tree must map page StructParents");
    let first_parent_array = nums[1].as_array().expect("page 0 parent array");
    assert!(
        !first_parent_array.is_empty(),
        "tagged text must have structure parents"
    );

    let first_page_id = parsed.page_iter().next().expect("first page");
    let first_page = parsed
        .get_object(first_page_id)
        .and_then(Object::as_dict)
        .expect("first page dict");
    assert_eq!(
        first_page
            .get(b"StructParents")
            .and_then(Object::as_i64)
            .expect("page StructParents"),
        0
    );
    assert_eq!(
        first_page
            .get(b"Tabs")
            .and_then(Object::as_name)
            .expect("page Tabs"),
        b"S"
    );

    let content = content_stream_text(&parsed);
    assert!(content.contains("/H1 << /MCID 0 >> BDC"));
    assert!(content.contains("/TH << /MCID"));
    assert!(content.contains("/TD << /MCID"));
    assert!(content.contains("/Div << /MCID"));
    assert!(content.contains("/Artifact BMC"));
    assert!(content.contains("EMC"));
}

#[test]
fn selfcheck_rejects_structparents_parent_tree_drift() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    let from = b"/StructParents 0";
    let to = b"/StructParents 9";
    let pos = bytes
        .windows(from.len())
        .position(|w| w == from)
        .expect("first page StructParents marker");
    bytes[pos..pos + from.len()].copy_from_slice(to);

    let err = selfcheck::verify(&bytes).expect_err("corrupt StructParents must fail");
    assert!(
        err.to_string().contains("/StructParents"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_unmapped_custom_structure_role() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    replace_once(&mut bytes, b"/ChancelaParagraph/P", b"/ChancelaParaGraft/P");

    let err = selfcheck::verify(&bytes).expect_err("unmapped role must fail");
    assert!(
        err.to_string().contains("unmapped custom role"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_invalid_table_topology() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    replace_once(&mut bytes, b"/S/TR", b"/S/TD");

    let err = selfcheck::verify(&bytes).expect_err("invalid table topology must fail");
    assert!(
        err.to_string().contains("tagged table topology"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn accessibility_selfcheck_rejects_invalid_table_header_scope() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    replace_once(&mut bytes, b"/Scope/Row", b"/Scope/Foo");

    let err = selfcheck::verify(&bytes).expect_err("invalid table header scope must fail");
    assert!(
        err.to_string().contains("unsupported /Scope"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_unbalanced_marked_content() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    replace_once(&mut bytes, b"EMC\n", b"   \n");

    let err = selfcheck::verify(&bytes).expect_err("unbalanced marked content must fail");
    assert!(
        err.to_string().contains("unclosed marked-content"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_unscoped_layout_artifact_painting() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    replace_once(&mut bytes, b"/Artifact BMC", b"/Artifact XXX");

    let err = selfcheck::verify(&bytes).expect_err("unscoped artifact drawing must fail");
    assert!(
        err.to_string().contains("outside an /Artifact"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_missing_display_doc_title_preference() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    replace_once(
        &mut bytes,
        b"/DisplayDocTitle true",
        b"/DisplayDocTitle null",
    );

    let err = selfcheck::verify(&bytes).expect_err("missing DisplayDocTitle must fail");
    assert!(
        err.to_string().contains("DisplayDocTitle"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_non_structure_tab_order() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    replace_once(&mut bytes, b"/Tabs/S", b"/Tabs/R");

    let err = selfcheck::verify(&bytes).expect_err("non-structure tab order must fail");
    assert!(
        err.to_string().contains("/Tabs"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_xmp_language_drift_from_catalog_lang() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    replace_once(
        &mut bytes,
        b"<rdf:li>pt-PT</rdf:li>",
        b"<rdf:li>zz-ZZ</rdf:li>",
    );

    let err = selfcheck::verify(&bytes).expect_err("XMP language drift must fail");
    assert!(
        err.to_string().contains("dc:language"),
        "unexpected self-check error: {err}"
    );
}

/// The pades byte-shape contract (C1–C12): the guarantees `chancela-pades::sign_pdf` relies on
/// when it appends its incremental signature update. This is the Wave-D-unblock surface e3 exercises
/// end-to-end.
#[test]
fn pades_signable_shape_holds() {
    let bytes = pdfa::write(&fixture()).expect("write");

    // The signer scans for its OWN "/Contents <" and "/ByteRange [0 " placeholders (first match).
    // The base document must contain neither, or the scan would latch onto our content.
    assert!(
        !bytes.windows(11).any(|w| w == b"/Contents <"),
        "base doc must not contain a `/Contents <` sequence"
    );
    assert!(
        !bytes.windows(10).any(|w| w == b"/ByteRange"),
        "base doc must not contain `/ByteRange`"
    );

    let parsed = Document::load_mem(&bytes).expect("load_mem (C11)");
    // C4: trailer /Root reference. C5: catalog /Pages reference.
    let root = parsed
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .expect("C4 /Root");
    let catalog = parsed.get_object(root).and_then(Object::as_dict).unwrap();
    let pages_ref = catalog
        .get(b"Pages")
        .and_then(Object::as_reference)
        .expect("C5 /Pages ref");
    // C6/C7: /Kids[0] is an indirect ref resolving to a /Page dictionary.
    let pages = parsed
        .get_object(pages_ref)
        .and_then(Object::as_dict)
        .unwrap();
    let first_kid = pages
        .get(b"Kids")
        .and_then(Object::as_array)
        .ok()
        .and_then(|k| k.first())
        .and_then(|k| k.as_reference().ok())
        .expect("C6 first kid ref");
    let page = parsed
        .get_object(first_kid)
        .and_then(Object::as_dict)
        .unwrap();
    assert_eq!(
        page.get(b"Type").and_then(Object::as_name).ok(),
        Some(&b"Page"[..])
    );
    // C2: no AcroForm. C3: no /Annots (absent is best). C12: no /Encrypt.
    assert!(!catalog.has(b"AcroForm"));
    assert!(!page.has(b"Annots"));
    assert!(!parsed.trailer.has(b"Encrypt"));
}

#[test]
fn output_is_deterministic() {
    let a = pdfa::write(&fixture()).expect("write a");
    let b = pdfa::write(&fixture()).expect("write b");
    assert_eq!(
        a, b,
        "same DocumentModel must produce byte-identical output"
    );
}

#[test]
fn legacy_model_without_layout_uses_the_product_default_deterministically() {
    let legacy = r#"{
        "title":"Compatibilidade",
        "entity_name":"Encosto Estratégico Lda",
        "entity_nipc":null,
        "subject":"Modelo anterior",
        "language":"pt-PT",
        "created_at":null,
        "blocks":[{"type":"Paragraph","runs":[{"text":"Texto estável.","bold":false,"italic":false}]}]
    }"#;
    let from_legacy: DocumentModel = serde_json::from_str(legacy).expect("legacy model parses");
    assert_eq!(from_legacy.document_layout, DocumentLayoutPolicy::default());

    let a = pdfa::write(&from_legacy).expect("write legacy model");
    let b = pdfa::write(&from_legacy).expect("rewrite legacy model");
    assert_eq!(a, b);

    let parsed = Document::load_mem(&a).expect("parse");
    assert_eq!(media_box(&parsed), [0.0, 0.0, 595.28, 841.89]);
    assert!(!first_page(&parsed).has(b"Rotate"));
}

#[test]
fn page_size_and_orientation_are_physical_media_boxes_without_rotate() {
    let cases = [
        (DocumentPageSize::A4, 595.28, 841.89),
        (DocumentPageSize::A5, 419.53, 595.28),
        (DocumentPageSize::Letter, 612.0, 792.0),
        (DocumentPageSize::Legal, 612.0, 1008.0),
    ];
    for (size, portrait_width, portrait_height) in cases {
        for (orientation, width, height) in [
            (
                DocumentOrientation::Portrait,
                portrait_width,
                portrait_height,
            ),
            (
                DocumentOrientation::Landscape,
                portrait_height,
                portrait_width,
            ),
        ] {
            let mut doc = fixture();
            doc.document_layout.page.size = size;
            doc.document_layout.page.orientation = orientation;
            let bytes = pdfa::write(&doc).expect("write configured page");
            let parsed = Document::load_mem(&bytes).expect("parse");
            assert_eq!(media_box(&parsed), [0.0, 0.0, width, height]);
            assert!(
                !first_page(&parsed).has(b"Rotate"),
                "{size:?} {orientation:?} must use a physical MediaBox swap"
            );
        }
    }
}

#[test]
fn margins_and_vertical_rhythm_change_content_geometry_and_page_count() {
    let mut narrow = DocumentModel::new("Margens", "Encosto Estratégico Lda", "Ritmo");
    narrow.blocks = (0..90)
        .map(|index| Block::Paragraph {
            runs: vec![Run {
                text: format!(
                    "Parágrafo {index} com texto suficiente para medir a paginação configurável."
                ),
                bold: false,
                italic: false,
            }],
        })
        .collect();
    narrow.document_layout.page.margins_mm.top = 5;
    narrow.document_layout.page.margins_mm.right = 5;
    narrow.document_layout.page.margins_mm.bottom = 5;
    narrow.document_layout.page.margins_mm.left = 15;
    narrow.document_layout.regions.footer_gap_mm = 0;
    narrow.document_layout.typography.line_spacing_percent = 100;
    narrow.document_layout.typography.paragraph_spacing_pt = 0;

    let narrow_bytes = pdfa::write(&narrow).expect("write compact layout");
    let narrow_pdf = Document::load_mem(&narrow_bytes).expect("parse");
    let narrow_content = content_stream_text(&narrow_pdf);
    let first_td = narrow_content
        .lines()
        .find(|line| line.ends_with(" Td"))
        .expect("first positioned text");
    assert!(
        first_td.starts_with("42.52 "),
        "15 mm left margin must become 42.52 pt, got {first_td}"
    );

    let mut spacious = narrow.clone();
    spacious.document_layout.page.margins_mm.top = 40;
    spacious.document_layout.page.margins_mm.right = 40;
    spacious.document_layout.page.margins_mm.bottom = 40;
    spacious.document_layout.page.margins_mm.left = 40;
    spacious.document_layout.regions.footer_gap_mm = 20;
    spacious.document_layout.typography.line_spacing_percent = 200;
    spacious.document_layout.typography.paragraph_spacing_pt = 24;
    assert!(
        pdfa::page_count(&spacious).expect("spacious count")
            > pdfa::page_count(&narrow).expect("compact count"),
        "larger margins and rhythm must consume more pages"
    );
}

#[test]
fn typography_selects_only_needed_embedded_type0_fonts() {
    let mut sans = fixture();
    sans.document_layout.typography.body_font_family = DocumentFontFamily::NotoSans;
    sans.document_layout.typography.header_font_family = DocumentFontFamily::NotoSans;
    sans.document_layout.typography.body_font_size_pt = 13;
    sans.document_layout.typography.header_font_size_pt = 12;
    let sans_bytes = pdfa::write(&sans).expect("write all-sans document");
    let sans_pdf = Document::load_mem(&sans_bytes).expect("parse");
    let page_id = sans_pdf.page_iter().next().expect("first page");
    let page_fonts = sans_pdf.get_page_fonts(page_id).expect("page fonts");
    assert_eq!(page_fonts.len(), 1, "same selected family must be shared");
    assert_eq!(
        page_fonts
            .values()
            .next()
            .expect("one page font")
            .get(b"BaseFont")
            .and_then(Object::as_name)
            .expect("BaseFont"),
        b"NotoSans"
    );
    let content = content_stream_text(&sans_pdf);
    assert!(content.contains("/F1 13.00 Tf"));
    assert!(
        content.contains("/F1 18.55 Tf"),
        "12 pt header policy must scale the document title deterministically"
    );
    assert!(
        content.contains("/F1 20.09 Tf"),
        "13 pt body policy must feed the level-one heading scale"
    );
    assert!(!content.contains("/F2 "));

    let mut scaled = sans.clone();
    scaled.document_layout.typography.heading_scale_percent = 150;
    let scaled_pdf =
        Document::load_mem(&pdfa::write(&scaled).expect("write scaled headings")).expect("parse");
    assert!(
        content_stream_text(&scaled_pdf).contains("/F1 30.14 Tf"),
        "150% heading scale must multiply the configured body-derived heading size"
    );

    let mut mixed = sans;
    mixed.document_layout.typography.header_font_family = DocumentFontFamily::NotoSerif;
    let mixed_bytes = pdfa::write(&mixed).expect("write mixed-font document");
    let mixed_pdf = Document::load_mem(&mixed_bytes).expect("parse");
    let page_id = mixed_pdf.page_iter().next().expect("first page");
    let page_fonts = mixed_pdf.get_page_fonts(page_id).expect("page fonts");
    assert_eq!(page_fonts.len(), 2);
    for (_, font) in page_fonts {
        assert_eq!(
            font.get(b"Subtype").and_then(Object::as_name).unwrap(),
            b"Type0"
        );
        assert!(font.has(b"ToUnicode"));
    }
    let content = content_stream_text(&mixed_pdf);
    assert!(content.contains("/F1 13.00 Tf"));
    assert!(
        content.contains("/F2 "),
        "header text must use the second face"
    );

    let mut header_only = DocumentModel::new("Cabeçalho", "Entidade", "Sem corpo");
    header_only.document_layout.typography.body_font_family = DocumentFontFamily::NotoSans;
    header_only.document_layout.typography.header_font_family = DocumentFontFamily::NotoSerif;
    let bytes = pdfa::write(&header_only).expect("write header-only document");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let page_id = parsed.page_iter().next().expect("first page");
    let page_fonts = parsed.get_page_fonts(page_id).expect("page fonts");
    assert_eq!(
        page_fonts.len(),
        1,
        "an unused body face must not be embedded"
    );
    assert_eq!(
        page_fonts
            .values()
            .next()
            .expect("header font")
            .get(b"BaseFont")
            .and_then(Object::as_name)
            .expect("BaseFont"),
        b"NotoSerif"
    );
}

#[test]
fn unusable_page_policy_fails_before_pdf_assembly() {
    let mut doc = fixture();
    doc.document_layout.page.size = DocumentPageSize::A5;
    doc.document_layout.page.margins_mm.left = 60;
    doc.document_layout.page.margins_mm.right = 60;
    let error = pdfa::write(&doc).expect_err("28 mm usable width must be rejected");
    assert!(
        error.to_string().contains("leaves only 28x170 mm usable"),
        "unexpected validation error: {error}"
    );
}

#[test]
fn pagination_produces_multiple_pages() {
    let mut doc = DocumentModel::new(
        "Documento Longo",
        "Encosto Estratégico Lda",
        "Teste de paginação",
    );
    // Enough paragraphs to overflow a single A4 page.
    doc.blocks = (0..120)
        .map(|i| Block::Paragraph {
            runs: vec![Run {
                text: format!(
                    "Parágrafo número {i}: texto de preenchimento com acentuação para forçar a \
                     mudança de página e exercitar a quebra de linha do motor de composição."
                ),
                bold: false,
                italic: false,
            }],
        })
        .collect();
    let bytes = pdfa::write(&doc).expect("write long doc");
    let parsed = Document::load_mem(&bytes).expect("parse");
    assert!(
        parsed.get_pages().len() > 1,
        "expected multiple pages, got {}",
        parsed.get_pages().len()
    );
}

#[test]
fn explicit_page_break_starts_a_new_page() {
    let mut doc = DocumentModel::new("Quebra", "Encosto Estratégico Lda", "PageBreak");
    doc.blocks = vec![
        Block::Paragraph {
            runs: vec![Run {
                text: "Primeira página.".to_string(),
                bold: false,
                italic: false,
            }],
        },
        Block::PageBreak,
        Block::Paragraph {
            runs: vec![Run {
                text: "Segunda página.".to_string(),
                bold: false,
                italic: false,
            }],
        },
    ];
    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    assert_eq!(parsed.get_pages().len(), 2);
}

#[test]
fn paragraph_flow_emits_real_unicode_spaces() {
    let mut doc = DocumentModel::new("T", "E", "S");
    doc.blocks = vec![Block::Paragraph {
        runs: vec![
            Run {
                text: "FlowAlpha ".to_string(),
                bold: false,
                italic: false,
            },
            Run {
                text: "FlowBeta FlowGamma".to_string(),
                bold: true,
                italic: false,
            },
        ],
    }];
    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let font = Font::load().expect("load bundled font");

    assert_text_fragment_sequence(
        &parsed,
        &[
            glyph_hex(&font, "FlowAlpha"),
            glyph_hex(&font, " "),
            glyph_hex(&font, "FlowBeta"),
            glyph_hex(&font, " "),
            glyph_hex(&font, "FlowGamma"),
        ],
    );
    assert_tounicode_maps_space(&parsed, &font);
}

#[test]
fn wrapped_key_value_values_emit_real_unicode_spaces() {
    let mut doc = DocumentModel::new("T", "E", "S");
    let leading_wrap_word = "WrapForcingPrefix".repeat(10);
    doc.blocks = vec![Block::KeyValue {
        rows: vec![KvRow {
            key: "Campo".to_string(),
            value: format!("{leading_wrap_word} WrappedSecond WrappedThird"),
        }],
    }];
    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let font = Font::load().expect("load bundled font");

    assert_text_fragment_sequence(
        &parsed,
        &[
            glyph_hex(&font, "WrappedSecond"),
            glyph_hex(&font, " "),
            glyph_hex(&font, "WrappedThird"),
        ],
    );
    assert_tounicode_maps_space(&parsed, &font);
}

#[test]
fn diacritics_survive_via_tounicode() {
    let mut doc = DocumentModel::new("Diacríticos", "Encosto Estratégico Lda", "ç ã õ á");
    doc.blocks = vec![Block::Paragraph {
        runs: vec![Run {
            text: "coração melão sótão látex ç ã õ á à â é ê í ó ô ú «aspas»".to_string(),
            bold: false,
            italic: false,
        }],
    }];
    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    // Find the uncompressed ToUnicode CMap stream.
    let cmap = parsed
        .objects
        .values()
        .filter_map(|o| o.as_stream().ok())
        .find(|s| s.content.windows(11).any(|w| w == b"beginbfchar"))
        .expect("a /ToUnicode bfchar CMap stream");
    let text = String::from_utf8_lossy(&cmap.content);
    // Each Portuguese diacritic must be recoverable (mapped to its UTF-16BE scalar).
    for (ch, hex) in [('ç', "00E7"), ('ã', "00E3"), ('õ', "00F5"), ('á', "00E1")] {
        assert!(
            text.contains(hex),
            "ToUnicode CMap is missing a mapping to U+{hex} ({ch})"
        );
    }
}

#[test]
fn metadata_is_uncompressed_pdfa2u() {
    let bytes = pdfa::write(&fixture()).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let catalog = catalog(&parsed);
    let meta_ref = catalog
        .get(b"Metadata")
        .and_then(Object::as_reference)
        .unwrap();
    let meta = parsed
        .get_object(meta_ref)
        .and_then(Object::as_stream)
        .unwrap();
    assert!(!meta.dict.has(b"Filter"), "XMP must not be compressed");
    let xmp = String::from_utf8_lossy(&meta.content);
    assert!(xmp.contains("<pdfaid:part>2</pdfaid:part>"));
    assert!(xmp.contains("<pdfaid:conformance>U</pdfaid:conformance>"));
}

#[test]
fn xmp_packet_carries_pdfua_identifier_only_when_claimed() {
    let doc = fixture();
    let metadata = pdfa::accessibility_report(&doc).metadata;

    // Without a claim: a plain, valid PDF/A-2U packet — no UA identifier, no extension schema.
    let without = String::from_utf8(crate::xmp::packet(&doc, &metadata, false)).unwrap();
    assert!(
        !without.contains("pdfuaid"),
        "no PDF/UA identifier without a claim"
    );
    assert!(!without.contains("pdfaExtension"));
    assert!(without.contains("<pdfaid:part>2</pdfaid:part>"));
    assert!(without.contains("<pdfaid:conformance>U</pdfaid:conformance>"));

    // With a claim: PDF/UA-1 identifier + mandatory pdfaExtension schema description, still a
    // valid PDF/A-2U packet.
    let with = String::from_utf8(crate::xmp::packet(&doc, &metadata, true)).unwrap();
    assert!(with.contains("xmlns:pdfuaid=\"http://www.aiim.org/pdfua/ns/id/\""));
    assert!(with.contains("<pdfuaid:part>1</pdfuaid:part>"));
    assert!(with.contains("<pdfaExtension:schemas>"));
    assert!(with.contains("<pdfaSchema:prefix>pdfuaid</pdfaSchema:prefix>"));
    assert!(with.contains(
        "<pdfaSchema:namespaceURI>http://www.aiim.org/pdfua/ns/id/</pdfaSchema:namespaceURI>"
    ));
    assert!(with.contains("<pdfaProperty:name>part</pdfaProperty:name>"));
    assert!(with.contains("<pdfaProperty:valueType>Integer</pdfaProperty:valueType>"));
    assert!(with.contains("<pdfaid:part>2</pdfaid:part>"));
    assert!(with.contains("<pdfaid:conformance>U</pdfaid:conformance>"));
    // The UA description is reused from the model subject.
    assert!(with.contains("<dc:description>"));
    assert!(with.contains("Deliberação sobre contas"));
}

#[test]
fn accessibility_metadata_falls_back_for_missing_title_language() {
    let mut doc = DocumentModel::new(" \t\n", "Encosto Estratégico Lda", "Sem título");
    doc.language = "  ".to_string();

    let report = pdfa::accessibility_report(&doc);
    assert_eq!(report.metadata.title.value, "Untitled Chancela document");
    assert!(!report.metadata.title.source_present);
    assert!(report.metadata.title.fallback_used);
    assert_eq!(report.metadata.language.value, "und");
    assert!(!report.metadata.language.source_present);
    assert!(report.metadata.language.fallback_used);
    assert!(!report.pdf_ua_claimed);

    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let catalog = catalog(&parsed);
    assert_eq!(
        catalog.get(b"Lang").and_then(Object::as_str).unwrap(),
        b"und"
    );
    let xmp = xmp_text(&parsed);
    assert!(xmp.contains("<rdf:li xml:lang=\"x-default\">Untitled Chancela document</rdf:li>"));
    assert!(xmp.contains("<rdf:li>und</rdf:li>"));
}

#[test]
fn implausible_language_metadata_is_reported_and_falls_back() {
    let mut doc = fixture();
    doc.language = "pt_PT".to_string();

    let report = pdfa::accessibility_report(&doc);
    assert_eq!(report.metadata.language.value, "und");
    assert!(report.metadata.language.source_present);
    assert!(report.metadata.language.fallback_used);
    assert!(!report.pdf_ua_claimed);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::NoAltTextModel)
    );

    let bytes = pdfa::write(&doc).expect("write");
    assert!(
        !bytes.windows(7).any(|w| w == b"pdfuaid"),
        "fallback metadata must not introduce PDF/UA identification"
    );
    let parsed = Document::load_mem(&bytes).expect("parse");
    let catalog = catalog(&parsed);
    assert_eq!(
        catalog.get(b"Lang").and_then(Object::as_str).unwrap(),
        b"und"
    );
    let xmp = xmp_text(&parsed);
    assert!(xmp.contains("<rdf:li>und</rdf:li>"));
    assert!(!xmp.contains("pt_PT"));
}

#[test]
fn long_non_ascii_title_is_preserved_in_report_and_xmp() {
    let title = format!(
        "São Tomé & Príncipe: ata extraordinária <revisão> \"final\" {}",
        vec!["ação"; 32].join(" ")
    );
    let doc = DocumentModel::new(format!("  {title}  "), "Encosto Estratégico Lda", "Teste");

    let report = pdfa::accessibility_report(&doc);
    assert_eq!(report.metadata.title.value, title);
    assert!(report.metadata.title.source_present);
    assert!(!report.metadata.title.fallback_used);
    assert!(report.to_json().contains("São Tomé & Príncipe"));
    assert!(report.to_json().contains("\\\"final\\\""));

    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let xmp = xmp_text(&parsed);
    assert!(xmp.contains("São Tomé &amp; Príncipe"));
    assert!(xmp.contains("&lt;revisão&gt;"));
    assert!(xmp.contains("&quot;final&quot;"));
}

#[test]
fn accessibility_default_fixture_reports_no_alt_text_model() {
    let report = pdfa::accessibility_report(&fixture());

    assert!(report.structure_tree_present);
    assert!(report.tagged_content_present);
    assert!(report.layout_artifacts_marked);
    assert!(report.display_doc_title);
    assert!(report.pages_use_structure_tab_order);
    assert!(!report.alt_text_model_present);
    assert!(report.pdf_ua_claimed);
    assert_eq!(
        report.pdf_ua_blocker_delta.delta_basis,
        "local_chancela_doc_writer_evidence_only"
    );
    assert!(report.pdf_ua_blocker_delta.pdf_ua_claimed);
    assert!(report.heading_hierarchy.document_title_tagged_as_h1);
    assert_eq!(report.heading_hierarchy.heading_count, 2);
    assert!(report.heading_hierarchy.no_skipped_levels);
    assert!(report.heading_hierarchy.unsupported_levels.is_empty());
    assert!(report.role_map.complete);
    assert!(report.role_map.missing_custom_roles.is_empty());
    assert!(
        report
            .role_map
            .mapped_roles
            .iter()
            .any(|entry| entry.custom_role == "ChancelaVoteTable"
                && entry.standard_role == "Table"
                && entry.required)
    );
    assert_eq!(report.table_semantics.key_value_table_count, 1);
    assert_eq!(report.table_semantics.vote_table_count, 1);
    assert!(report.table_semantics.complete);
    assert!(report.table_semantics.key_value_tables_have_table_semantics);
    assert!(report.table_semantics.vote_tables_have_table_semantics);
    assert_eq!(report.table_semantics.row_header_cell_count, 4);
    assert_eq!(report.table_semantics.column_header_cell_count, 4);
    assert_eq!(report.table_semantics.data_cell_count, 8);
    assert_eq!(report.table_semantics.table_rows_missing_header_count, 0);
    assert!(report.table_semantics.key_value_row_headers_tagged);
    assert!(report.table_semantics.vote_table_headers_tagged);
    assert!(report.table_semantics.vote_table_column_headers_tagged);
    assert!(report.table_semantics.vote_table_row_headers_tagged);
    assert!(report.table_semantics.row_header_cells_have_scope_row);
    assert!(report.table_semantics.column_header_cells_have_scope_column);
    assert!(report.table_semantics.header_cells_have_scope);
    assert!(report.structure_tree.catalog_mark_info_marked);
    assert!(report.structure_tree.catalog_struct_tree_root);
    assert_eq!(
        report.structure_tree.struct_tree_root_type,
        "StructTreeRoot"
    );
    assert_eq!(
        report.structure_tree.document_element_role,
        "ChancelaDocument"
    );
    assert!(report.structure_tree.parent_tree_present);
    assert!(report.structure_tree.parent_tree_next_key_tracks_pages);
    assert!(report.structure_tree.pages_have_struct_parents);
    assert!(report.structure_tree.page_struct_parents_are_page_indexes);
    assert!(report.structure_tree.pages_use_structure_tab_order);
    assert!(report.structure_tree.complete_for_local_profile);
    assert!(report.structure_depth.bounded_local_profile);
    assert_eq!(report.structure_depth.max_depth, 4);
    assert_eq!(report.structure_depth.top_level_semantic_block_count, 9);
    assert_eq!(report.structure_depth.table_count, 2);
    assert_eq!(report.structure_depth.table_row_count, 5);
    assert_eq!(report.structure_depth.table_cell_count, 16);
    assert!(
        report
            .structure_depth
            .document_root_children_are_top_level_semantic_blocks
    );
    assert!(report.structure_depth.tables_contain_rows_only);
    assert!(
        report
            .structure_depth
            .rows_contain_header_or_data_cells_only
    );
    assert!(report.structure_depth.row_and_cell_roles_are_table_scoped);
    assert!(report.structure_depth.complete_for_local_profile);
    assert_eq!(report.marked_content.structure_element_count, 31);
    assert_eq!(report.marked_content.marked_leaf_element_count, 23);
    assert_eq!(report.marked_content.table_cell_marked_leaf_count, 16);
    assert_eq!(report.marked_content.artifact_scope_count, 6);
    assert!(report.marked_content.semantic_leaves_have_marked_content);
    assert!(report.marked_content.parent_tree_maps_page_mcids);
    assert!(report.marked_content.artifacts_are_marked_without_mcid);
    assert!(report.marked_content.complete_for_local_profile);
    assert_eq!(report.artifact_marking.known_layout_artifact_count, 6);
    assert_eq!(
        report.artifact_marking.known_layout_artifact_targets,
        vec![
            "layout:header-rule".to_string(),
            "block:4:vote-table-header-rule".to_string(),
            "block:4:vote-table-footer-rule".to_string(),
            "block:5:rule".to_string(),
            "block:6:signature-line:0".to_string(),
            "block:6:signature-line:1".to_string(),
        ]
    );
    assert_eq!(report.artifact_marking.artifact_scope_operator, "BMC");
    assert!(!report.artifact_marking.artifacts_use_mcid);
    assert!(report.artifact_marking.path_painting_scoped_as_artifact);
    assert_eq!(report.non_text_content.known_decorative_block_count, 6);
    assert!(
        report
            .non_text_content
            .writer_owned_decorative_artifacts_accounted_for
    );
    assert!(
        report
            .non_text_content
            .missing_decorative_artifacts
            .is_empty()
    );
    assert!(report.non_text_content.complete);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::NoAltTextModel)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::KeyValueTablesNotTaggedAsTables)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::VoteTablesNotTaggedAsTables)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::VoteTableHeadersNotTagged)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::MissingStructTreeRoot)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::ContentIsNotTagged)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::MissingRoleMap)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::LayoutArtifactsNotMarked)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::LimitedTaggedStructure)
    );
    // A conforming document has no remaining blockers; every stable blocker (including the retired
    // LimitedTaggedStructure) is now cleared.
    assert!(report.pdf_ua_blockers.is_empty());
    assert_eq!(
        report.pdf_ua_blocker_delta.remaining_blockers,
        report.pdf_ua_blockers
    );
    assert_eq!(report.pdf_ua_blocker_delta.remaining_count, 0);
    assert_eq!(
        report.pdf_ua_blocker_delta.cleared_count,
        pdfa::PdfUaBlocker::ALL.len()
    );
    assert!(
        report
            .pdf_ua_blocker_delta
            .cleared_blockers
            .contains(&pdfa::PdfUaBlocker::MissingStructTreeRoot)
    );
    assert!(
        report
            .pdf_ua_blocker_delta
            .cleared_blockers
            .contains(&pdfa::PdfUaBlocker::NoAltTextModel)
    );
    assert!(
        report
            .pdf_ua_blocker_delta
            .cleared_blockers
            .contains(&pdfa::PdfUaBlocker::LimitedTaggedStructure)
    );
}

#[test]
fn accessibility_heading_hierarchy_reports_skipped_and_unsupported_levels() {
    let mut doc = DocumentModel::new("Hierarchy", "Encosto Estratégico Lda", "Teste");
    doc.blocks = vec![
        Block::Heading {
            level: 3,
            text: "Skipped h2".to_string(),
        },
        Block::Heading {
            level: 4,
            text: "Unsupported h4".to_string(),
        },
    ];

    let report = pdfa::accessibility_report(&doc);

    assert_eq!(report.heading_hierarchy.heading_count, 2);
    assert_eq!(report.heading_hierarchy.max_observed_level, 4);
    assert!(!report.heading_hierarchy.no_skipped_levels);
    assert_eq!(report.heading_hierarchy.unsupported_levels, vec![4]);
    assert_eq!(
        report.pdf_ua_blockers,
        vec![
            pdfa::PdfUaBlocker::HeadingHierarchySkipsLevels,
            pdfa::PdfUaBlocker::UnsupportedHeadingLevel,
        ]
    );
    assert!(!report.pdf_ua_claimed);
}

#[test]
fn accessibility_role_map_and_table_semantics_are_reported() {
    let report = pdfa::accessibility_report(&fixture());

    assert_eq!(
        report.role_map.required_custom_roles,
        vec![
            "ChancelaDocument".to_string(),
            "ChancelaDocumentTitle".to_string(),
            "ChancelaHeaderMetadata".to_string(),
            "ChancelaHeading1".to_string(),
            "ChancelaHeading2".to_string(),
            "ChancelaParagraph".to_string(),
            "ChancelaKeyValue".to_string(),
            "ChancelaVoteTable".to_string(),
            "ChancelaSignatureBlock".to_string(),
        ]
    );
    assert!(report.role_map.present);
    assert!(report.role_map.standard_targets_only);
    assert!(report.role_map.complete);
    assert!(
        report
            .role_map
            .mapped_roles
            .iter()
            .any(|entry| entry.custom_role == "ChancelaKeyValue"
                && entry.standard_role == "Table"
                && entry.required)
    );
    assert!(
        report
            .role_map
            .mapped_roles
            .iter()
            .any(|entry| entry.custom_role == "ChancelaHeading3"
                && entry.standard_role == "H3"
                && !entry.required)
    );
    assert_eq!(report.table_semantics.key_value_table_count, 1);
    assert_eq!(report.table_semantics.vote_table_count, 1);
    assert!(report.table_semantics.key_value_tables_have_table_semantics);
    assert!(report.table_semantics.vote_tables_have_table_semantics);
    assert_eq!(report.table_semantics.row_header_cell_count, 4);
    assert_eq!(report.table_semantics.column_header_cell_count, 4);
    assert_eq!(report.table_semantics.data_cell_count, 8);
    assert_eq!(report.table_semantics.table_rows_missing_header_count, 0);
    assert!(report.table_semantics.key_value_row_headers_tagged);
    assert!(report.table_semantics.vote_table_headers_tagged);
    assert!(report.table_semantics.vote_table_column_headers_tagged);
    assert!(report.table_semantics.vote_table_row_headers_tagged);
    assert!(report.table_semantics.row_header_cells_have_scope_row);
    assert!(report.table_semantics.column_header_cells_have_scope_column);
    assert!(report.table_semantics.header_cells_have_scope);
    assert!(report.table_semantics.complete);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::KeyValueTablesNotTaggedAsTables)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::VoteTablesNotTaggedAsTables)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::VoteTableHeadersNotTagged)
    );
}

#[test]
fn accessibility_report_records_space_emission_with_pdfua_claim() {
    let report = pdfa::accessibility_report(&fixture());

    assert!(report.inter_word_spaces_emitted);
    assert!(report.pdf_ua_claimed);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::KeyValueTablesNotTaggedAsTables)
    );

    let json = report.to_json();
    assert!(json.contains("\"version\":12"));
    assert!(json.contains("\"row_header_cell_count\":4"));
    assert!(json.contains("\"column_header_cell_count\":4"));
    assert!(json.contains("\"header_cells_have_scope\":true"));
    assert!(json.contains("\"table_rows_missing_header_count\":0"));
    assert!(json.contains("\"structure_depth\":{"));
    assert!(json.contains("\"marked_content\":{"));
    assert!(json.contains("\"bounded_local_profile\":true"));
    assert!(json.contains("\"inter_word_spaces_emitted\":true"));
    assert!(json.contains("\"pdf_ua_claimed\":true"));
    assert!(json.contains("\"pdf_ua\":{\"claimed\":true,\"part\":1,\"conformance\":\"1\""));
    assert!(!json.contains("\"pdf_ua_claimed\":false"));
}

#[test]
fn accessibility_bounded_local_pdf_diagnostics_are_emitted_with_pdfua_claim() {
    let report = pdfa::accessibility_report(&fixture());

    assert!(report.pdf_ua_claimed);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::LimitedTaggedStructure)
    );
    assert!(report.structure_tree.complete_for_local_profile);
    assert!(
        report
            .role_map
            .mapped_roles
            .iter()
            .any(|entry| entry.custom_role == "ChancelaDocument"
                && entry.standard_role == "Document"
                && entry.required)
    );
    assert!(report.artifact_marking.layout_artifacts_marked);
    assert_eq!(report.artifact_marking.artifact_scope_operator, "BMC");
    assert!(!report.artifact_marking.artifacts_use_mcid);

    let json = report.to_json();
    assert!(json.contains("\"version\":12"));
    assert!(json.contains(
        "\"pdf_ua_blocker_delta\":{\"delta_basis\":\"local_chancela_doc_writer_evidence_only\""
    ));
    assert!(json.contains("\"structure_tree\":{"));
    assert!(json.contains("\"catalog_mark_info_marked\":true"));
    assert!(json.contains("\"mapped_roles\":["));
    assert!(json.contains(
        "\"custom_role\":\"ChancelaVoteTable\",\"standard_role\":\"Table\",\"required\":true"
    ));
    assert!(json.contains("\"known_layout_artifact_targets\":["));
    assert!(json.contains("\"artifact_scope_operator\":\"BMC\""));
    assert!(json.contains("\"artifacts_use_mcid\":false"));
    assert!(json.contains("\"pdf_ua_claimed\":true"));
    assert!(json.contains("\"remaining_blockers\":[]"));
    assert!(json.contains("\"cleared_count\":13"));
    assert!(json.contains("\"remaining_count\":0"));
    assert!(!json.contains("\"pdf_ua_claimed\":false"));
    // The machine report describes the target profile via a pdf_ua object, not the raw pdfuaid tag.
    assert!(!json.contains("pdfuaid"));

    // A conforming document carries the PDF/UA-1 identifier in its XMP.
    let bytes = pdfa::write(&fixture()).expect("write");
    assert!(
        bytes.windows(7).any(|w| w == b"pdfuaid"),
        "a conforming document must carry PDF/UA identification metadata"
    );
}

#[test]
fn accessibility_explicit_alt_text_decorative_model_claims_pdf_ua() {
    let mut doc = DocumentModel::new(
        "Ata com metadados de acessibilidade",
        "Encosto Estratégico Lda",
        "Modelo explicito",
    );
    doc.blocks = vec![
        Block::Paragraph {
            runs: vec![Run {
                text: "Conteudo textual principal.".to_string(),
                bold: false,
                italic: false,
            }],
        },
        Block::Rule,
    ];
    let alt_text_model = pdfa::AltTextModel {
        all_non_text_content_accounted_for: true,
        text_alternatives: vec![pdfa::TextAlternative::new(
            "asset:company-seal",
            "Company seal",
        )],
        decorative_artifacts: vec![
            pdfa::DecorativeArtifact::header_rule(),
            pdfa::DecorativeArtifact::block_rule(1),
        ],
    };

    let report = pdfa::accessibility_report(
        pdfa::AccessibilityInput::new(&doc).with_alt_text_model(&alt_text_model),
    );

    assert!(report.alt_text_model_present);
    assert!(report.non_text_content.complete);
    assert!(report.pdf_ua_claimed);
    assert!(report.pdf_ua_blockers.is_empty());
    assert!(report.pdf_ua_blocker_delta.remaining_blockers.is_empty());
    assert_eq!(
        report.pdf_ua_blocker_delta.cleared_count,
        pdfa::PdfUaBlocker::ALL.len()
    );
    assert_eq!(report.pdf_ua_blocker_delta.remaining_count, 0);
    assert!(report.pdf_ua_blocker_delta.pdf_ua_claimed);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::NoAltTextModel)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::MissingStructTreeRoot)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::ContentIsNotTagged)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::MissingRoleMap)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::LayoutArtifactsNotMarked)
    );
}

#[test]
fn accessibility_page_breaks_do_not_require_decorative_accounting() {
    let mut doc = DocumentModel::new("Quebra", "Encosto Estratégico Lda", "PageBreak");
    doc.blocks = vec![
        Block::Paragraph {
            runs: vec![Run {
                text: "Primeira página.".to_string(),
                bold: false,
                italic: false,
            }],
        },
        Block::PageBreak,
        Block::Paragraph {
            runs: vec![Run {
                text: "Segunda página.".to_string(),
                bold: false,
                italic: false,
            }],
        },
    ];

    let alt_text_model = pdfa::AltTextModel {
        all_non_text_content_accounted_for: true,
        text_alternatives: vec![],
        decorative_artifacts: vec![pdfa::DecorativeArtifact::header_rule()],
    };

    let report = pdfa::accessibility_report(
        pdfa::AccessibilityInput::new(&doc).with_alt_text_model(&alt_text_model),
    );

    assert_eq!(report.non_text_content.known_decorative_block_count, 1);
    assert!(
        report
            .non_text_content
            .missing_decorative_artifacts
            .is_empty()
    );
    assert!(report.alt_text_model_present);
    assert!(report.non_text_content.complete);
    assert!(report.pdf_ua_claimed);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::NoAltTextModel)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::NonTextContentNotAccountedFor)
    );

    let bytes = pdfa::write(&doc).expect("write page-break PDF");
    assert!(
        bytes.windows(7).any(|w| w == b"pdfuaid"),
        "a conforming multi-page document must carry PDF/UA identification"
    );
    let parsed = Document::load_mem(&bytes).expect("parse page-break PDF");
    assert_eq!(parsed.get_pages().len(), 2);
}

#[test]
fn accessibility_non_text_accounting_covers_current_block_variants() {
    let mut doc = DocumentModel::new("Variantes", "Encosto Estratégico Lda", "Todos os blocos");
    doc.blocks = vec![
        Block::Heading {
            level: 1,
            text: "Secao".to_string(),
        },
        Block::Paragraph {
            runs: vec![Run {
                text: "Texto".to_string(),
                bold: false,
                italic: false,
            }],
        },
        Block::KeyValue {
            rows: vec![KvRow {
                key: "Data".to_string(),
                value: "2026-07-11".to_string(),
            }],
        },
        Block::VoteTable {
            rows: vec![VoteRow {
                label: "Ponto 1".to_string(),
                favor: 1,
                against: 0,
                abstain: 0,
            }],
        },
        Block::SignatureBlock {
            slots: vec![SignatureSlot {
                role: "Presidente".to_string(),
                name: "Amelia Marques".to_string(),
            }],
        },
        Block::PageBreak,
        Block::Rule,
    ];

    let report = pdfa::accessibility_report(&doc);

    assert_eq!(report.artifact_marking.known_layout_artifact_count, 5);
    assert_eq!(report.non_text_content.known_decorative_block_count, 5);
    assert!(
        report
            .non_text_content
            .writer_owned_decorative_artifacts_accounted_for
    );
    assert!(report.non_text_content.complete);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::NoAltTextModel)
    );
    assert!(report.pdf_ua_claimed);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::LimitedTaggedStructure)
    );
}

#[test]
fn accessibility_non_text_accounting_reports_missing_and_invalid_entries() {
    let mut doc = DocumentModel::new("Decorativos", "Encosto Estratégico Lda", "Teste");
    doc.blocks = vec![Block::PageBreak, Block::Rule];
    let alt_text_model = pdfa::AltTextModel {
        all_non_text_content_accounted_for: true,
        text_alternatives: vec![pdfa::TextAlternative::new("asset:seal", " ")],
        decorative_artifacts: vec![
            pdfa::DecorativeArtifact::block_rule(0),
            pdfa::DecorativeArtifact::new(" "),
        ],
    };

    let report = pdfa::accessibility_report(
        pdfa::AccessibilityInput::new(&doc).with_alt_text_model(&alt_text_model),
    );

    assert!(report.non_text_content.model_supplied);
    assert_eq!(report.non_text_content.text_alternative_count, 1);
    assert_eq!(report.non_text_content.decorative_artifact_count, 2);
    assert_eq!(report.non_text_content.known_decorative_block_count, 2);
    assert!(
        report
            .non_text_content
            .writer_owned_decorative_artifacts_accounted_for
    );
    assert!(
        report
            .non_text_content
            .missing_decorative_artifacts
            .is_empty()
    );
    assert_eq!(report.non_text_content.invalid_text_alternative_count, 1);
    assert_eq!(report.non_text_content.invalid_decorative_artifact_count, 1);
    assert!(!report.non_text_content.complete);
    assert_eq!(
        report.pdf_ua_blockers,
        vec![pdfa::PdfUaBlocker::NonTextContentNotAccountedFor]
    );
    assert!(!report.pdf_ua_claimed);
}

#[test]
fn accessibility_report_json_is_deterministic() {
    let a = pdfa::accessibility_report(&fixture()).to_json();
    let b = pdfa::accessibility_report(&fixture()).to_json();
    assert_eq!(a, b);
    assert!(a.starts_with(
        "{\"version\":12,\"pdf_ua_claimed\":true,\"pdf_ua\":{\"claimed\":true,\"part\":1,\"conformance\":\"1\",\"scope\":\"pre_signature_document\"},\"pdf_ua_blocker_delta\":{"
    ));
    assert!(a.contains("\"delta_basis\":\"local_chancela_doc_writer_evidence_only\""));
    assert!(a.contains("\"remaining_blockers\":[]"));
    assert!(a.contains("\"cleared_count\":13"));
    assert!(a.contains("\"remaining_count\":0"));
    assert!(a.contains("\"structure_tree\":{"));
    assert!(a.contains("\"mapped_roles\":["));
    assert!(a.contains("\"key_value_tables_have_table_semantics\":true"));
    assert!(a.contains("\"row_header_cells_have_scope_row\":true"));
    assert!(a.contains("\"column_header_cells_have_scope_column\":true"));
    assert!(a.contains("\"known_layout_artifact_targets\":["));
    assert!(a.contains("\"pdf_ua_blockers\":[]"));
    assert!(!a.contains("\"pdf_ua_claimed\":false"));
}

#[test]
fn conforming_document_carries_full_pdf_ua_identification_and_gate_passes() {
    let doc = fixture();
    let report = pdfa::accessibility_report(&doc);
    assert!(report.pdf_ua_claimed);
    assert!(report.pdf_ua_blockers.is_empty());

    let bytes = pdfa::write(&doc).expect("write");
    // Determinism: the same model reproduces identical bytes, UA identifier included.
    assert_eq!(bytes, pdfa::write(&doc).expect("write again"));

    let parsed = Document::load_mem(&bytes).expect("parse");
    let xmp = xmp_text(&parsed);
    // PDF/UA-1 identifier + mandatory extension schema.
    assert!(xmp.contains("xmlns:pdfuaid=\"http://www.aiim.org/pdfua/ns/id/\""));
    assert!(xmp.contains("<pdfuaid:part>1</pdfuaid:part>"));
    assert!(xmp.contains("<pdfaExtension:schemas>"));
    assert!(xmp.contains("<pdfaSchema:prefix>pdfuaid</pdfaSchema:prefix>"));
    // Still a valid PDF/A-2U file.
    assert!(xmp.contains("<pdfaid:part>2</pdfaid:part>"));
    assert!(xmp.contains("<pdfaid:conformance>U</pdfaid:conformance>"));

    let catalog = catalog(&parsed);
    assert!(
        !catalog
            .get(b"Lang")
            .and_then(Object::as_str)
            .unwrap()
            .is_empty()
    );
    let mark_info = catalog.get(b"MarkInfo").and_then(Object::as_dict).unwrap();
    assert!(matches!(
        mark_info.get(b"Marked"),
        Ok(Object::Boolean(true))
    ));
    let str_ref = catalog
        .get(b"StructTreeRoot")
        .and_then(Object::as_reference)
        .unwrap();
    let str_root = parsed
        .get_object(str_ref)
        .and_then(Object::as_dict)
        .unwrap();
    let role_map = str_root.get(b"RoleMap").and_then(Object::as_dict).unwrap();
    assert!(!role_map.is_empty());
    let viewer_prefs = catalog
        .get(b"ViewerPreferences")
        .and_then(Object::as_dict)
        .unwrap();
    assert!(matches!(
        viewer_prefs.get(b"DisplayDocTitle"),
        Ok(Object::Boolean(true))
    ));

    // The generated bytes pass the enforced UA self-check gate.
    selfcheck::verify(&bytes).expect("UA gate passes for a conforming document");
}

#[test]
fn selfcheck_rejects_pdfua_claim_without_extension_schema() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    // Corrupt the mandatory extension-schema block in place (same length keeps xref offsets valid)
    // while leaving the pdfuaid identifier — an inconsistent, false UA claim the gate must reject.
    replace_once(
        &mut bytes,
        b"<pdfaExtension:schemas>",
        b"<pdfaXxtension:schemas>",
    );

    let err =
        selfcheck::verify(&bytes).expect_err("a pdfuaid claim without its extension schema fails");
    assert!(
        err.to_string().contains("pdfaExtension schema"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn skipped_heading_document_makes_no_pdf_ua_claim() {
    // Negative fixture: a heading skips from the implicit H1 to H3 — the report must decline the
    // UA claim and the writer must emit a plain PDF/A-2U file with no PDF/UA identifier.
    let mut doc = DocumentModel::new("Salto", "Encosto Estratégico Lda", "Cabeçalhos");
    doc.blocks = vec![
        Block::Heading {
            level: 3,
            text: "Salto para h3".to_string(),
        },
        Block::Paragraph {
            runs: vec![Run {
                text: "Corpo.".to_string(),
                bold: false,
                italic: false,
            }],
        },
    ];

    let report = pdfa::accessibility_report(&doc);
    assert!(!report.pdf_ua_claimed);
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::HeadingHierarchySkipsLevels)
    );

    // write() still succeeds (valid PDF/A-2U) but carries no UA claim.
    let bytes = pdfa::write(&doc).expect("write");
    assert!(
        !bytes.windows(7).any(|w| w == b"pdfuaid"),
        "a non-conforming document must not claim PDF/UA"
    );
    selfcheck::verify(&bytes).expect("plain PDF/A-2U still self-checks");
}

#[test]
fn pdf_ua_is_claimed_for_conforming_document() {
    let report = pdfa::accessibility_report(&fixture());
    assert!(report.pdf_ua_claimed);
    assert!(report.structure_tree_present);
    assert!(report.tagged_content_present);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::MissingStructTreeRoot)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::ContentIsNotTagged)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::KeyValueTablesNotTaggedAsTables)
    );
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::LimitedTaggedStructure)
    );

    let bytes = pdfa::write(&fixture()).expect("write");
    assert!(
        bytes.windows(7).any(|w| w == b"pdfuaid"),
        "a conforming document must carry PDF/UA identification metadata"
    );
    let parsed = Document::load_mem(&bytes).expect("parse");
    let catalog = catalog(&parsed);
    assert!(catalog.has(b"StructTreeRoot"));
    let mark_info = catalog
        .get(b"MarkInfo")
        .and_then(Object::as_dict)
        .expect("honest MarkInfo dictionary");
    assert!(matches!(
        mark_info.get(b"Marked"),
        Ok(Object::Boolean(true))
    ));
}

// --- The (A)/(B) checks added by t12-e1: ICC, glyph-level /ToUnicode, colour and transparency ----
//
// Every one of these is mutation-verified with an **equal-length** mutant. That matters twice over:
// a length-changing edit invalidates every xref offset after it, so the file fails with a generic
// "object missing" that proves nothing about the rule under test; and a check that has never been
// observed to fail is indistinguishable from a check that cannot fail.

/// Locate `needle` and return its offset, panicking with a readable message when absent.
fn offset_of(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| panic!("missing byte pattern: {}", String::from_utf8_lossy(needle)))
}

/// Change one hex digit in place, wrapping `f` to `0`, so the mutant stays the same length *and*
/// stays syntactically valid hex — the edit must be caught by the rule, not by the parser.
fn bump_hex_digit(bytes: &mut [u8], at: usize) {
    bytes[at] = match bytes[at] {
        b'f' | b'F' => b'0',
        b'9' => b'A',
        digit => digit + 1,
    };
}

#[test]
fn selfcheck_rejects_a_structurally_broken_icc_profile() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    // `acsp` at header offset 36 is the ICC magic. Without it the bytes are not a profile at all,
    // and the old `/N == 3` check would have waved them through regardless.
    replace_once(&mut bytes, b"acsp", b"acsq");

    let err = selfcheck::verify(&bytes).expect_err("a non-ICC profile must fail");
    assert!(
        err.to_string().contains("acsp"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_a_tampered_icc_profile() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    // A byte in the profile's tag *data*, past the tag table, so the structural checks all still
    // pass: this is a well-formed ICC profile that is simply no longer the one we ship, and the
    // colour of every page is no longer the colour we promised.
    let profile_start = offset_of(&bytes, b"acsp") - 36;
    bytes[profile_start + 400] ^= 0xff;

    let err = selfcheck::verify(&bytes).expect_err("a tampered profile must fail");
    assert!(
        err.to_string().contains("not the shipped sRGB profile"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_a_tounicode_entry_the_font_disagrees_with() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    // Repoint the first bfchar mapping at a different Unicode scalar. The CMap stays well-formed
    // and still has an entry for every glyph shown — only its *content* is now a lie, which is
    // precisely what a presence check cannot see.
    let first_entry = offset_of(&bytes, b"beginbfchar\n") + b"beginbfchar\n".len();
    let target = offset_of(&bytes[first_entry..], b"> <") + first_entry + 3;
    bump_hex_digit(&mut bytes, target + 3);

    let err = selfcheck::verify(&bytes).expect_err("a wrong /ToUnicode target must fail");
    assert!(
        err.to_string().contains("/ToUnicode maps glyph"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_a_glyph_shown_without_a_tounicode_entry() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    // Repoint a bfchar *source* code instead: the mapped glyph now has no entry, and some other
    // glyph gains a spurious one. The leading digit is bumped rather than the trailing one so the
    // mutant lands far from any glyph in use — a collision would trip the duplicate-key rule
    // instead, which is a different check.
    let first_entry = offset_of(&bytes, b"beginbfchar\n") + b"beginbfchar\n".len();
    bump_hex_digit(&mut bytes, first_entry + 1);

    let err = selfcheck::verify(&bytes).expect_err("an unmapped shown glyph must fail");
    let message = err.to_string();
    assert!(
        message.contains("has no /ToUnicode entry") || message.contains("which no page shows"),
        "unexpected self-check error: {message}"
    );
}

#[test]
fn selfcheck_rejects_a_width_that_disagrees_with_the_embedded_font() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    // The `/W` array is `cid [width] cid [width] …`; bump a digit of the first width. The array
    // stays well-formed, so only the agreement with `hmtx` can catch it.
    let widths = offset_of(&bytes, b"/W[");
    let first_width = offset_of(&bytes[widths + 3..], b"[") + widths + 4;
    bytes[first_width] = if bytes[first_width] == b'9' {
        b'1'
    } else {
        bytes[first_width] + 1
    };

    let err = selfcheck::verify(&bytes).expect_err("a wrong /W width must fail");
    assert!(
        err.to_string().contains("the embedded hmtx gives"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_a_devicecmyk_content_operator() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    // `0 g` (DeviceGray fill) becomes `0 k` (DeviceCMYK). The file has an RGB output intent only,
    // so CMYK has no defined rendering — the exact rule veraPDF enforces on colour.
    replace_once(&mut bytes, b"\n0 g\n", b"\n0 k\n");

    let err = selfcheck::verify(&bytes).expect_err("DeviceCMYK must fail");
    assert!(
        err.to_string().contains("DeviceCMYK"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_a_transparency_operator() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    // `gs` is the only door to blend modes, soft masks and constant alpha. Nothing else in the
    // file needs to change for this to be a transparency-bearing document.
    replace_once(&mut bytes, b"\n0 g\n", b"\ngs\n\n");

    let err = selfcheck::verify(&bytes).expect_err("an ExtGState operator must fail");
    assert!(
        err.to_string().contains("ExtGState"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn selfcheck_rejects_a_non_font_page_resource() {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    // Rename the page's only resource category. Any name but `/Font` is a construct the writer
    // does not emit — an XObject, an ExtGState, a colour space — and the closed profile says so.
    replace_once(&mut bytes, b"/Resources<</Font", b"/Resources<</Xfnt");

    let err = selfcheck::verify(&bytes).expect_err("a foreign page resource must fail");
    assert!(
        err.to_string().contains("font-only resource profile"),
        "unexpected self-check error: {err}"
    );
}

#[test]
fn writing_a_character_the_face_lacks_is_refused_rather_than_silently_blanked() {
    // A character with no glyph in the bundled face resolves to glyph 0 (.notdef). The writer would
    // then record "glyph 0 means 漢" — so this character renders as a blank box, and the *next*
    // missing character renders as the same blank box but extracts as 漢. Silent, wrong, and
    // invisible to any check that only asks whether a /ToUnicode CMap exists.
    let mut doc = fixture();
    doc.blocks.push(Block::Paragraph {
        runs: vec![Run {
            text: "漢字".to_string(),
            bold: false,
            italic: false,
        }],
    });

    let err = pdfa::write(&doc).expect_err("a glyph the face lacks must not be silently emitted");
    assert!(
        err.to_string().contains(".notdef"),
        "unexpected self-check error: {err}"
    );
}

// --- tg4: the rules underneath `verify()` that had never been observed to fail -------------------
//
// `verify()`'s *entry* behaviour was well covered; most of the machinery beneath it was not — over
// half of `selfcheck/mod.rs`'s functions and two thirds of `icc.rs`'s lines never executed, because
// every one of them lives on a `return Err(...)` that no test had ever reached. A rule that has
// never been observed to fail is indistinguishable from a rule that cannot fail, so each of these
// drives one specific rule with one **equal-length** mutant and asserts that rule's own diagnostic.
//
// Equal length is not a style preference: a length-changing edit shifts every subsequent xref
// offset, and the file then fails with a generic "object missing" that attributes nothing. Where a
// rule is only reachable by changing the file's length, it is left uncovered and said so in
// `.orchestration/logs/tg4-coverage.md` rather than covered by a test that proves something else.

/// The offset of the embedded ICC profile's first byte. The profile is stored uncompressed, so its
/// `acsp` signature at header offset 36 locates it in the file.
fn icc_profile_start(bytes: &[u8]) -> usize {
    offset_of(bytes, b"acsp") - 36
}

/// Write the fixture, hand the embedded ICC profile to `mutate`, and return the self-check error.
fn icc_mutant(mutate: impl FnOnce(&mut [u8], usize)) -> String {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    let start = icc_profile_start(&bytes);
    mutate(&mut bytes, start);
    selfcheck::verify(&bytes)
        .expect_err("the mutated ICC profile must be refused")
        .to_string()
}

/// Assert `haystack` contains `needle`, reporting the whole diagnostic when it does not — a
/// mismatch usually means a *different, also correct* rule fired first, which is a fact about the
/// mutant rather than about the rule under test.
fn assert_diagnostic(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected a diagnostic naming {needle:?}, got: {haystack}"
    );
}

#[test]
fn selfcheck_rejects_an_icc_profile_whose_header_lies_about_its_length() {
    // The header's declared size is the first thing any ICC consumer trusts. A profile that
    // declares more bytes than it carries is read past its end by anything less careful than this.
    let err = icc_mutant(|bytes, start| bytes[start + 3] = bytes[start + 3].wrapping_add(1));
    assert_diagnostic(&err, "but the stream holds");
}

#[test]
fn selfcheck_rejects_an_icc_profile_of_an_unsupported_version() {
    // ICC v5 (iccMAX) is a different specification; PDF/A output intents are v2 or v4.
    let err = icc_mutant(|bytes, start| bytes[start + 8] = 5);
    assert_diagnostic(&err, "major version is 5");
}

#[test]
fn selfcheck_rejects_an_icc_profile_that_is_not_an_output_intent_class() {
    // `link`/`abst`/`nmcl` profiles cannot describe a destination colour space at all.
    let err = icc_mutant(|bytes, start| bytes[start + 12..start + 16].copy_from_slice(b"link"));
    assert_diagnostic(&err, "device class /link");
}

#[test]
fn selfcheck_rejects_an_icc_profile_whose_colour_space_contradicts_the_stream() {
    // The single most consequential ICC mismatch: a CMYK profile labelled `/N 3`. Every colour in
    // the document would then be interpreted against the wrong space, and the old `/N == 3` gate
    // saw nothing wrong with it.
    let err = icc_mutant(|bytes, start| bytes[start + 16..start + 20].copy_from_slice(b"CMYK"));
    assert_diagnostic(&err, "has 4 components but the stream declares /N 3");
}

#[test]
fn selfcheck_rejects_an_icc_profile_in_a_colour_space_pdfa_does_not_define() {
    let err = icc_mutant(|bytes, start| bytes[start + 16..start + 20].copy_from_slice(b"YCbr"));
    assert_diagnostic(&err, "outside the PDF/A output-intent set");
}

#[test]
fn selfcheck_rejects_an_icc_profile_with_a_foreign_connection_space() {
    // The PCS is what makes the profile composable with any other; only XYZ and Lab are defined.
    let err = icc_mutant(|bytes, start| bytes[start + 20..start + 24].copy_from_slice(b"RGB "));
    assert_diagnostic(&err, "connection space RGB");
}

#[test]
fn selfcheck_rejects_an_icc_profile_with_an_undefined_rendering_intent() {
    // Intents are 0..=3. Anything else is a number no renderer has a rule for.
    let err =
        icc_mutant(|bytes, start| bytes[start + 64..start + 68].copy_from_slice(&[0, 0, 0, 9]));
    assert_diagnostic(&err, "rendering intent 9 is outside");
}

#[test]
fn selfcheck_rejects_an_icc_tag_table_that_does_not_fit_in_the_profile() {
    // The tag count drives a loop over 12-byte entries; an inflated count is the classic way to
    // walk a parser off the end of a buffer. This module bounds-checks it instead.
    let err = icc_mutant(|bytes, start| {
        bytes[start + 128..start + 132].copy_from_slice(&[0, 0, 0xff, 0xff])
    });
    assert_diagnostic(&err, "which does not fit in");
}

#[test]
fn selfcheck_rejects_an_icc_tag_pointing_outside_the_profile_body() {
    // Each tag entry is (signature, offset, size). A tag whose extent leaves the profile is a
    // read the profile cannot satisfy — checked per entry, not merely in aggregate.
    let err = icc_mutant(|bytes, start| {
        // The first entry's offset field, at 132 + 4.
        bytes[start + 136..start + 140].copy_from_slice(&[0, 0xff, 0xff, 0]);
    });
    assert_diagnostic(&err, "outside the profile body");
}

#[test]
fn selfcheck_rejects_an_rgb_icc_profile_missing_a_mandatory_tag() {
    // ICC.1:2010 §8.3 makes these nine tags mandatory for an RGB matrix/TRC display profile.
    // Renaming one leaves a structurally walkable table that no longer describes a white point.
    let err = icc_mutant(|bytes, start| {
        let table = start + 132;
        let at = offset_of(&bytes[table..], b"wtpt") + table;
        bytes[at..at + 4].copy_from_slice(b"wtpq");
    });
    assert_diagnostic(&err, "missing the mandatory wtpt tag");
}

// --- The structural rules in `selfcheck/mod.rs` --------------------------------------------------

/// Write the fixture, apply `mutate`, and return the self-check error.
fn mutant(mutate: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut bytes = pdfa::write(&fixture()).expect("write");
    mutate(&mut bytes);
    selfcheck::verify(&bytes)
        .expect_err("the mutated document must be refused")
        .to_string()
}

#[test]
fn selfcheck_rejects_a_document_that_is_not_pdf_1_7() {
    let err = mutant(|bytes| replace_once(bytes, b"%PDF-1.7", b"%PDF-1.4"));
    assert_diagnostic(&err, "header is not %PDF-1.7");
}

#[test]
fn selfcheck_rejects_a_missing_binary_header_marker() {
    // PDF/A requires the second line to be a comment carrying a byte > 127, which is what tells a
    // transfer agent the file is binary and must not be line-ending-translated.
    let err = mutant(|bytes| bytes[9..16].copy_from_slice(b"%aaaa\r\n"));
    assert_diagnostic(&err, "binary header marker");
}

#[test]
fn selfcheck_rejects_an_lzw_compressed_stream() {
    // LZW is prohibited outright in PDF/A. This writer emits no compressed stream at all, so
    // there is no `/Filter` to rewrite; `/ToUnicode` is exactly as long as `/LZWDecode` and the
    // rule is a byte scan over the whole file, run before anything is parsed.
    let err = mutant(|bytes| replace_once(bytes, b"/ToUnicode", b"/LZWDecode"));
    assert_diagnostic(&err, "LZWDecode filter is prohibited");
}

#[test]
fn selfcheck_rejects_a_catalog_carrying_additional_actions() {
    // `/AA` runs actions on document events — the one thing an archival format must not carry,
    // because the file's meaning would then depend on a reader's behaviour.
    // `/MarkInfo` is the same length and appears only in the catalog; losing it would itself be
    // an error, but the `/AA` rule is checked first, so this attributes cleanly.
    let err = mutant(|bytes| replace_once(bytes, b"/MarkInfo", b"/AA      "));
    assert_diagnostic(&err, "/AA additional-actions");
}

#[test]
fn selfcheck_rejects_xmp_that_claims_the_wrong_pdfa_part() {
    let err = mutant(|bytes| {
        replace_once(
            bytes,
            b"<pdfaid:part>2</pdfaid:part>",
            b"<pdfaid:part>3</pdfaid:part>",
        )
    });
    assert_diagnostic(&err, "pdfaid:part = 2");
}

#[test]
fn selfcheck_rejects_xmp_that_claims_the_wrong_conformance_level() {
    // The conformance letter is the difference between "text is extractable" (U) and merely
    // "renders identically" (B) — the whole point of the level this writer targets.
    let err = mutant(|bytes| {
        replace_once(
            bytes,
            b"<pdfaid:conformance>U</pdfaid:conformance>",
            b"<pdfaid:conformance>B</pdfaid:conformance>",
        )
    });
    assert_diagnostic(&err, "pdfaid:conformance = U");
}

#[test]
fn selfcheck_rejects_an_output_intent_that_is_not_a_pdfa_output_intent() {
    let err = mutant(|bytes| replace_once(bytes, b"GTS_PDFA1", b"GTS_PDFX3"));
    assert_diagnostic(&err, "/S is not /GTS_PDFA1");
}

#[test]
fn selfcheck_rejects_an_icc_stream_declaring_the_wrong_component_count() {
    // `/N` is the stream's own claim about the profile. It must be 3, and it must agree with the
    // profile's data colour space — two separate assertions, and this is the first.
    let err = mutant(|bytes| {
        let at = offset_of(bytes, b"/N 3");
        bytes[at + 3] = b'4';
    });
    assert_diagnostic(&err, "/N is 4, not 3");
}

#[test]
fn selfcheck_rejects_a_catalog_that_does_not_mark_its_tagged_content() {
    // `/MarkInfo /Marked true` is what tells a reader the tags are real. Without it the whole
    // structure tree is decoration, and every accessibility claim resting on it is false.
    let err = mutant(|bytes| replace_once(bytes, b"/Marked true", b"/Marked null"));
    assert_diagnostic(&err, "does not mark emitted tagged content");
}

#[test]
fn selfcheck_rejects_a_role_map_entry_that_maps_to_a_non_standard_role() {
    // A custom role is only meaningful because the `/RoleMap` translates it into a role a reader
    // knows. Mapping it to another invented name leaves the tag tree unreadable while looking
    // fully populated — which a presence check on `/RoleMap` cannot see.
    let err = mutant(|bytes| {
        replace_once(
            bytes,
            b"/ChancelaVoteTable/Table",
            b"/ChancelaVoteTable/Tabld",
        )
    });
    assert_diagnostic(&err, "maps to non-standard role");
}

#[test]
fn selfcheck_rejects_tagged_content_with_no_mcid() {
    // A `BDC` scope without an `/MCID` cannot be reached from the structure tree: the content is
    // drawn, and no tag points at it. This is the "untagged real content" failure in UA terms.
    let err = mutant(|bytes| replace_once(bytes, b"/MCID ", b"/MCIE "));
    assert_diagnostic(&err, "tagged content has no /MCID");
}

#[test]
fn selfcheck_rejects_a_parent_tree_with_no_array_for_a_page() {
    // The `/ParentTree` is the reverse index from marked content back to structure. A page whose
    // `/StructParents` key has no array is a page whose tags are one-way.
    let err = mutant(|bytes| {
        let at = offset_of(bytes, b"/Nums[") + b"/Nums[".len();
        bytes[at] = b'9';
    });
    assert_diagnostic(&err, "has no array for page");
}

#[test]
fn selfcheck_rejects_a_page_font_that_is_not_a_composite_type0_font() {
    // A simple font shows single-byte codes, which the glyph-level `/ToUnicode` check cannot
    // interpret. Rejecting it outright is what stops a simple font becoming the one place a font
    // escapes that check.
    let err = mutant(|bytes| replace_once(bytes, b"/Subtype/Type0", b"/Subtype/Type1"));
    assert_diagnostic(&err, "the writer emits only Type0");
}

#[test]
fn selfcheck_rejects_a_font_with_no_embedded_program() {
    // Without `/FontFile2` the file depends on the reader having the face installed — the exact
    // dependency on the outside world that PDF/A exists to remove.
    let err = mutant(|bytes| replace_once(bytes, b"/FontFile2", b"/FontFilez"));
    assert_diagnostic(&err, "not embedded as a /FontFile2");
}

#[test]
fn selfcheck_rejects_xmp_whose_title_is_blank() {
    // `dc:title` is what a reader announces the document as; a whitespace-only one satisfies every
    // presence check and tells the reader nothing.
    let err = mutant(|bytes| {
        let start = offset_of(bytes, b"<rdf:li xml:lang=\"x-default\">")
            + b"<rdf:li xml:lang=\"x-default\">".len();
        let end = offset_of(&bytes[start..], b"</rdf:li>") + start;
        bytes[start..end].fill(b' ');
    });
    assert_diagnostic(&err, "dc:title value is empty");
}

#[test]
fn selfcheck_rejects_xmp_with_no_declared_language() {
    let err = mutant(|bytes| replace_once(bytes, b"<dc:language>", b"<dc:languagx>"));
    assert_diagnostic(&err, "missing dc:language");
}

#[test]
fn selfcheck_rejects_a_pdfua_namespace_that_claims_a_part_other_than_1() {
    // The `pdfuaid` namespace being present is what opens the UA gate. Claiming part 2 through it
    // is a claim against a specification this writer has asserted nothing about.
    let err = mutant(|bytes| {
        replace_once(
            bytes,
            b"<pdfuaid:part>1</pdfuaid:part>",
            b"<pdfuaid:part>2</pdfuaid:part>",
        )
    });
    assert_diagnostic(&err, "pdfuaid:part = 1");
}

#[test]
fn selfcheck_rejects_a_ua_claiming_document_whose_headings_skip_a_level() {
    // UA / G5. The writer cannot produce this (it declines to claim UA when headings skip), so the
    // rule is only reachable by mutation — and without one it would never have been observed to
    // fire at all.
    let err = mutant(|bytes| replace_once(bytes, b"/S/ChancelaHeading2", b"/S/ChancelaHeading3"));
    assert_diagnostic(&err, "skips a level");
}

// --- The tagged-structure topology and the page/content plumbing under it -----------------------

#[test]
fn selfcheck_rejects_a_trailer_whose_id_halves_disagree() {
    // ISO 19005-2 6.1.3: `/ID` is two equal 16-byte strings. The pair is what ties the revisions of
    // a signed document together, so halves that differ make the chain unverifiable — and a
    // presence check on `/ID` sees nothing wrong.
    let err = mutant(|bytes| {
        let at = offset_of(bytes, b"/ID");
        let first = offset_of(&bytes[at..], b"<") + at;
        let second = offset_of(&bytes[first + 1..], b"<") + first + 1;
        bump_hex_digit(bytes, second + 1);
    });
    assert_diagnostic(&err, "not two equal 16-byte strings");
}

#[test]
fn selfcheck_rejects_a_parent_tree_next_key_that_does_not_match_the_page_count() {
    // `/ParentTreeNextKey` is the next free `/StructParents` key. Wrong, a later incremental update
    // that adds a tagged annotation would reuse a live key and silently re-parent existing content.
    let err = mutant(|bytes| {
        let at = offset_of(bytes, b"/ParentTreeNextKey ") + b"/ParentTreeNextKey ".len();
        bytes[at] = if bytes[at] == b'9' {
            b'1'
        } else {
            bytes[at] + 1
        };
    });
    assert_diagnostic(&err, "/ParentTreeNextKey is");
}

#[test]
fn selfcheck_rejects_a_struct_tree_root_of_the_wrong_type() {
    let err = mutant(|bytes| replace_once(bytes, b"/Type/StructTreeRoot", b"/Type/StructTreeRoos"));
    assert_diagnostic(&err, "/StructTreeRoot has the wrong /Type");
}

#[test]
fn selfcheck_rejects_a_page_with_no_content_stream() {
    // Every other check reasons about the same decoded page content. A page whose `/Contents` the
    // checker cannot reach must stop the run rather than let those checks pass vacuously.
    let err = mutant(|bytes| replace_once(bytes, b"/Contents", b"/Contentz"));
    assert_diagnostic(&err, "has no /Contents");
}

#[test]
fn selfcheck_rejects_a_text_font_with_no_tounicode_cmap() {
    // Without a `/ToUnicode` the text renders and does not extract — the difference between
    // PDF/A-2B and the 2U level this writer claims.
    let err = mutant(|bytes| replace_once(bytes, b"/ToUnicode", b"/ToUnicodf"));
    assert_diagnostic(&err, "breaks the \"u\"");
}

#[test]
fn selfcheck_rejects_a_type0_font_with_no_resolvable_descendant() {
    // A composite font's widths and glyph ids live in its descendant CIDFont; without one there is
    // nothing for the `/W`-versus-`hmtx` agreement to be checked against.
    let err = mutant(|bytes| replace_once(bytes, b"/DescendantFonts", b"/DescendantFontz"));
    assert_diagnostic(&err, "descendant CIDFont");
}

#[test]
fn selfcheck_rejects_a_page_that_repeats_a_marked_content_id() {
    // `/MCID`s are the keys the `/ParentTree` indexes. A repeat makes two runs of content claim the
    // same tag, so one of them is silently attributed to the wrong structure element.
    let err = mutant(|bytes| replace_once(bytes, b"/MCID 1", b"/MCID 0"));
    assert_diagnostic(&err, "repeats marked-content /MCID");
}

#[test]
fn selfcheck_rejects_an_artifact_opened_with_bdc_instead_of_bmc() {
    // An artifact is content with no semantic meaning, so it carries no `/MCID` and must be opened
    // with `BMC`. Opened with `BDC` it claims to be tagged content that the structure tree has no
    // entry for.
    let err = mutant(|bytes| replace_once(bytes, b"/Artifact BMC", b"/Artifact BDC"));
    assert_diagnostic(&err, "/Artifact with BDC instead of BMC");
}

#[test]
fn selfcheck_rejects_a_data_cell_carrying_a_header_scope() {
    // `/Scope` is what associates a header with the cells it describes. On a `/TD` it is a claim
    // that a data cell heads a row or column — which is how a screen reader ends up announcing the
    // wrong header for every value in the table.
    let err = mutant(|bytes| replace_once(bytes, b"/S/TH", b"/S/TD"));
    assert_diagnostic(&err, "/TD carries a header /Scope attribute");
}

#[test]
fn selfcheck_rejects_table_header_attributes_not_owned_by_table() {
    // An attribute dictionary's `/O` names the standard that defines it. Owned by anything but
    // `/Table`, the `/Scope` beside it is not the table-scope attribute at all.
    let err = mutant(|bytes| replace_once(bytes, b"/O/Table", b"/O/Tabld"));
    assert_diagnostic(&err, "not owned by /Table");
}

#[test]
fn selfcheck_rejects_a_structure_leaf_whose_child_is_not_a_marked_content_reference() {
    // A leaf element reaches its content through an `/MCR`. Anything else there is a structure tree
    // that looks populated and points at nothing.
    let err = mutant(|bytes| replace_once(bytes, b"/Type/MCR", b"/Type/MCS"));
    assert_diagnostic(&err, "is not an /MCR dictionary");
}

// --- Page furniture (running header, running footer, marginal side text) -------------------------

/// One positioned text-showing operator, with the marked-content scope it sits in.
#[derive(Debug, Clone, PartialEq)]
struct PositionedText {
    /// `true` when the operator sits inside an `/Artifact` scope rather than a tagged one.
    artifact: bool,
    x: f32,
    y: f32,
    size: f32,
    /// The text matrix, when the fragment was positioned by `Tm` rather than `Td`.
    matrix: Option<[f32; 4]>,
}

fn page_content_streams(parsed: &Document) -> Vec<String> {
    parsed
        .page_iter()
        .map(|page_id| {
            let page = parsed
                .get_object(page_id)
                .and_then(Object::as_dict)
                .expect("page dictionary");
            let content_ref = page
                .get(b"Contents")
                .and_then(Object::as_reference)
                .expect("page contents reference");
            let content = parsed
                .get_object(content_ref)
                .and_then(Object::as_stream)
                .expect("page content stream");
            String::from_utf8_lossy(&content.content).into_owned()
        })
        .collect()
}

/// Walk one page's content stream, pairing every `Tj` with the position and scope in force.
fn positioned_text(page_content: &str) -> Vec<PositionedText> {
    let mut out = Vec::new();
    let mut artifact_depth = 0usize;
    let mut scope_depth = 0usize;
    let (mut x, mut y, mut size) = (0.0f32, 0.0f32, 0.0f32);
    let mut matrix: Option<[f32; 4]> = None;
    for raw in page_content.lines() {
        let line = raw.trim();
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match tokens.last().copied() {
            Some("BMC") | Some("BDC") => {
                scope_depth += 1;
                if line.starts_with("/Artifact") {
                    artifact_depth += 1;
                }
            }
            Some("EMC") => {
                scope_depth = scope_depth.saturating_sub(1);
                artifact_depth = artifact_depth.min(scope_depth);
            }
            Some("Tf") if tokens.len() == 3 => size = tokens[1].parse().expect("font size"),
            Some("Td") if tokens.len() == 3 => {
                x = tokens[0].parse().expect("Td x");
                y = tokens[1].parse().expect("Td y");
                matrix = None;
            }
            Some("Tm") if tokens.len() == 7 => {
                matrix = Some([
                    tokens[0].parse().expect("Tm a"),
                    tokens[1].parse().expect("Tm b"),
                    tokens[2].parse().expect("Tm c"),
                    tokens[3].parse().expect("Tm d"),
                ]);
                x = tokens[4].parse().expect("Tm e");
                y = tokens[5].parse().expect("Tm f");
            }
            Some("Tj") => out.push(PositionedText {
                artifact: artifact_depth > 0,
                x,
                y,
                size,
                matrix,
            }),
            _ => {}
        }
    }
    out
}

/// Whether a fragment is turned 90 degrees. Synthesised italics also carry a `Tm`, so the matrix
/// itself — not merely its presence — is what distinguishes rotated marginal text.
fn is_rotated(item: &PositionedText) -> bool {
    matches!(item.matrix, Some([0.0, _, _, 0.0]))
}

/// A document whose body overflows a page, so furniture has real body text to collide with.
fn dense_body(paragraphs: usize) -> DocumentModel {
    let mut doc = DocumentModel::new(
        "Livro de atas",
        "Encosto Estratégico Lda",
        "Ensaio de mobiliário de página",
    );
    doc.created_at = Some("2026-07-06T10:30:00Z".to_string());
    doc.blocks = (0..paragraphs)
        .map(|index| Block::Paragraph {
            runs: vec![Run {
                text: format!(
                    "Parágrafo {index} com texto suficiente para encher a coluna de texto e \
                     obrigar a paginação a transbordar para a página seguinte."
                ),
                bold: false,
                italic: false,
            }],
        })
        .collect();
    doc
}

fn furnished(paragraphs: usize) -> DocumentModel {
    let mut doc = dense_body(paragraphs);
    let furniture = &mut doc.document_layout.furniture;
    furniture.header.enabled = true;
    furniture.header.text = "{{ entity_name }} — {{ title }}".to_string();
    furniture.footer.enabled = true;
    furniture.footer.text = "{{ page }} / {{ page_count }}".to_string();
    furniture.side_text.enabled = true;
    furniture.side_text.text = "{{ subject }}".to_string();
    doc
}

#[test]
fn page_furniture_is_off_by_default_and_omitted_from_the_policy_wire_form() {
    // The whole byte-stability argument rests on this: a policy authored before furniture existed
    // and a policy that declines it must be the same bytes, or every stored `document_layout_json`
    // would re-digest differently the moment this field landed.
    let policy = DocumentLayoutPolicy::default();
    assert!(!policy.furniture.draws_anything());
    let json = serde_json::to_string(&policy).expect("policy serializes");
    assert!(
        !json.contains("furniture"),
        "the all-disabled default must stay off the wire, got {json}"
    );

    let pre_furniture = r#"{
        "page":{"size":"A4","orientation":"Portrait",
                "margins_mm":{"top":20,"right":20,"bottom":20,"left":20}},
        "typography":{"body_font_family":"NotoSerif","body_font_size_pt":10,
                      "header_font_family":"NotoSerif","header_font_size_pt":11,
                      "footer_font_family":"NotoSerif","footer_font_size_pt":9,
                      "line_spacing_percent":140,"paragraph_spacing_pt":6,
                      "heading_scale_percent":100},
        "regions":{"header_gap_mm":4,"footer_gap_mm":4}
    }"#;
    let restored: DocumentLayoutPolicy =
        serde_json::from_str(pre_furniture).expect("a stored pre-furniture policy still parses");
    assert_eq!(
        restored, policy,
        "an absent key must mean today's behaviour"
    );

    // …and the same model rendered under both is the same file, byte for byte.
    let mut from_stored = fixture();
    from_stored.document_layout = restored;
    assert_eq!(
        pdfa::write(&from_stored).expect("write from stored policy"),
        pdfa::write(&fixture()).expect("write from default policy"),
    );
}

#[test]
fn page_furniture_reserves_its_band_and_body_text_never_enters_it() {
    // The test that matters: a page full of body text, with all three pieces of furniture on.
    // Furniture takes its space out of the text column, so the body reflows around it. Nothing
    // here re-implements the engine's arithmetic — every bound is read off the furniture the
    // engine actually emitted.
    let doc = furnished(40);
    let bytes = pdfa::write(&doc).expect("write furnished document");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let pages = page_content_streams(&parsed);
    assert!(pages.len() > 1, "the fixture must overflow one page");

    for (page_index, page) in pages.iter().enumerate() {
        let text = positioned_text(page);
        let (furniture, body): (Vec<_>, Vec<_>) = text.into_iter().partition(|item| item.artifact);
        assert_eq!(
            furniture.len(),
            3,
            "page {page_index} must carry exactly the header, footer and side text"
        );
        assert!(
            !body.is_empty(),
            "page {page_index} must carry body text to collide with"
        );

        let upright: Vec<_> = furniture.iter().filter(|f| !is_rotated(f)).collect();
        assert_eq!(upright.len(), 2, "header and footer are upright");
        let header = upright.iter().map(|f| f.y).fold(f32::MIN, f32::max);
        let footer = upright.iter().map(|f| f.y).fold(f32::MAX, f32::min);
        let side = furniture
            .iter()
            .find(|f| is_rotated(f))
            .expect("rotated side text");

        for item in &body {
            assert!(
                item.y + item.size <= header,
                "page {page_index}: body text at y={} rises into the header band (baseline {header})",
                item.y
            );
            assert!(
                item.y >= footer + item.size,
                "page {page_index}: body text at y={} drops into the footer band (baseline {footer})",
                item.y
            );
            assert!(
                item.x >= side.x + side.size * 0.5,
                "page {page_index}: body text at x={} runs into the marginal band (baseline {})",
                item.x,
                side.x
            );
        }
    }
}

#[test]
fn enabling_furniture_reflows_the_body_instead_of_overprinting_it() {
    // The corollary of reserving space: the same blocks need more pages once furniture is on. If
    // furniture were painted into the margin without reserving, this count would not move — and
    // the overlap test above would be the only thing standing between a footer and a body line.
    let plain = dense_body(40);
    let with_furniture = furnished(40);
    assert!(
        pdfa::page_count(&with_furniture).expect("furnished count")
            >= pdfa::page_count(&plain).expect("plain count"),
        "furniture must never buy back space"
    );

    // …and the space it costs is visible directly: the first body baseline drops by the reserve.
    let mut header_only = dense_body(6);
    header_only.document_layout.furniture.header.enabled = true;
    header_only.document_layout.furniture.header.text =
        "{{ entity_name }} — {{ page }}".to_string();

    let first_body_top = |doc: &DocumentModel| -> f32 {
        let bytes = pdfa::write(doc).expect("write");
        let parsed = Document::load_mem(&bytes).expect("parse");
        positioned_text(&page_content_streams(&parsed)[0])
            .into_iter()
            .filter(|item| !item.artifact)
            .map(|item| item.y)
            .fold(f32::MIN, f32::max)
    };
    let reserved = first_body_top(&header_only);
    let unreserved = first_body_top(&dense_body(6));
    assert!(
        reserved < unreserved,
        "a running header must push the body down, got {reserved} vs {unreserved}"
    );
}

#[test]
fn page_furniture_is_emitted_as_artifacts_carrying_no_mcid() {
    // Repeated page apparatus is not document content. Marked as an artifact and kept out of the
    // structure tree, a screen reader skips it; tagged as content, it would read the entity name
    // and "3 / 7" between every paragraph on every page.
    let doc = furnished(40);
    let bytes = pdfa::write(&doc).expect("write furnished document");
    let parsed = Document::load_mem(&bytes).expect("parse");

    for (page_index, page) in page_content_streams(&parsed).iter().enumerate() {
        for item in positioned_text(page) {
            // Every furniture fragment is the artifact one; nothing else on the page is.
            assert_eq!(
                item.artifact,
                item.size == f32::from(doc.document_layout.typography.footer_font_size_pt),
                "page {page_index}: artifact scoping and furniture must coincide"
            );
        }
        // Artifact scopes are BMC and never carry an /MCID — the invariant `selfcheck` enforces
        // and `ArtifactMarkingReport.artifacts_use_mcid` reports.
        for line in page.lines().map(str::trim) {
            if line.starts_with("/Artifact") {
                assert!(line.ends_with(" BMC"), "artifact scope must be BMC: {line}");
                assert!(
                    !line.contains("/MCID"),
                    "artifact must carry no MCID: {line}"
                );
            }
        }
    }

    let report = pdfa::accessibility_report(&doc);
    assert!(report.artifact_marking.layout_artifacts_marked);
    assert!(!report.artifact_marking.artifacts_use_mcid);
    assert_eq!(report.artifact_marking.page_furniture_artifact_count, 3);
    assert!(
        report
            .artifact_marking
            .known_layout_artifact_targets
            .iter()
            .any(|target| target == "layout:page-furniture:side-text"),
        "furniture must be enumerated as writer-owned decorative content"
    );
    assert!(
        report.pdf_ua_claimed,
        "furnished output still claims PDF/UA"
    );
}

#[test]
fn page_furniture_constructors_name_the_targets_the_report_enumerates() {
    // `DecorativeArtifact::page_furniture_*` is the surface a caller uses to declare the running
    // header, running footer and marginal side text decorative in an `AltTextModel`. It is only
    // worth anything if it names the SAME targets the writer enumerates for itself: a constructor
    // saying `layout:page-furniture:head` would satisfy every other test while never matching, and
    // the caller would be declaring a piece that does not exist.
    //
    // Both sides are therefore pinned against LITERALS rather than against each other. They share
    // `furniture_target` today, so asserting one against the other would hold no matter what either
    // said; only a literal notices the day the shared helper's format changes.
    const EXPECTED: [&str; 3] = [
        "layout:page-furniture:header",
        "layout:page-furniture:footer",
        "layout:page-furniture:side-text",
    ];

    let furniture = [
        pdfa::DecorativeArtifact::page_furniture_header(),
        pdfa::DecorativeArtifact::page_furniture_footer(),
        pdfa::DecorativeArtifact::page_furniture_side_text(),
    ];
    assert_eq!(
        furniture
            .iter()
            .map(|artifact| artifact.target.as_str())
            .collect::<Vec<_>>(),
        EXPECTED,
        "the caller-facing constructors renamed a furniture piece"
    );

    let doc = furnished(8);
    let report = pdfa::accessibility_report(&doc);
    let targets = &report.artifact_marking.known_layout_artifact_targets;

    // The same three, in order, and no fourth: a piece added to the writer without a constructor
    // would leave a caller unable to name it, which is how these three came to be unused at all.
    let furniture_targets = targets
        .iter()
        .filter(|target| target.starts_with("layout:page-furniture:"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        furniture_targets, EXPECTED,
        "the report enumerates a different set of furniture pieces than the constructors name"
    );
    assert_eq!(
        report.artifact_marking.page_furniture_artifact_count,
        EXPECTED.len(),
        "all three furniture pieces draw in this document"
    );

    // A document that draws no furniture enumerates none of them — the count is per enabled piece,
    // not a constant.
    let bare = dense_body(4);
    let bare_report = pdfa::accessibility_report(&bare);
    assert_eq!(
        bare_report.artifact_marking.page_furniture_artifact_count,
        0
    );
    assert!(
        !bare_report
            .artifact_marking
            .known_layout_artifact_targets
            .iter()
            .any(|target| target.starts_with("layout:page-furniture:"))
    );
}

#[test]
fn marginal_side_text_is_rotated_by_the_text_matrix_only() {
    // Rotation lives in the text matrix, not a page `/Rotate` and not a form XObject, so the
    // glyphs stay in the page's own space and nothing downstream has to know the text is turned.
    let mut left = dense_body(6);
    left.document_layout.furniture.side_text.enabled = true;
    left.document_layout.furniture.side_text.text = "Livro de atas".to_string();
    let bytes = pdfa::write(&left).expect("write left-edge side text");
    let parsed = Document::load_mem(&bytes).expect("parse");
    assert!(
        first_page(&parsed).get(b"Rotate").is_err(),
        "the page must not be rotated"
    );
    let rotated = positioned_text(&page_content_streams(&parsed)[0])
        .into_iter()
        .find(is_rotated)
        .expect("rotated fragment");
    assert!(rotated.artifact, "marginal text is an artifact");
    // Bottom-to-top at the binding edge.
    assert_eq!(rotated.matrix, Some([0.0, 1.0, -1.0, 0.0]));

    let mut right = left.clone();
    right.document_layout.furniture.side_text.edge = DocumentSideTextEdge::Right;
    let right_bytes = pdfa::write(&right).expect("write right-edge side text");
    let right_parsed = Document::load_mem(&right_bytes).expect("parse");
    let right_rotated = positioned_text(&page_content_streams(&right_parsed)[0])
        .into_iter()
        .find(is_rotated)
        .expect("rotated fragment");
    // Top-to-bottom at the fore edge.
    assert_eq!(right_rotated.matrix, Some([0.0, -1.0, 1.0, 0.0]));
    assert!(
        right_rotated.x > rotated.x,
        "the fore-edge band sits on the other side of the page"
    );
}

#[test]
fn footer_resolves_the_page_number_against_the_page_count_on_every_page() {
    let mut doc = dense_body(40);
    doc.document_layout.furniture.footer.enabled = true;
    doc.document_layout.furniture.footer.text = "Página {{ page }} de {{ page_count }}".to_string();
    let bytes = pdfa::write(&doc).expect("write paginated footer");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let pages = page_content_streams(&parsed);
    let total = pages.len();
    assert!(total > 1);

    let font = Font::load_family(DocumentFontFamily::NotoSerif).expect("serif");
    for (index, page) in pages.iter().enumerate() {
        let expected = glyph_hex(&font, &format!("Página {} de {total}", index + 1));
        assert!(
            page.contains(&format!("<{expected}> Tj")),
            "page {index} must carry its own resolved footer"
        );
    }
}

#[test]
fn footer_against_book_capacity_resolves_only_when_the_document_carries_one() {
    let mut with_capacity = dense_body(4);
    with_capacity.page_capacity = Some(100);
    with_capacity.document_layout.furniture.footer.enabled = true;
    with_capacity.document_layout.furniture.footer.text =
        "Página {{ page }} de {{ page_capacity }}".to_string();
    let bytes = pdfa::write(&with_capacity).expect("write capacity footer");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let font = Font::load_family(DocumentFontFamily::NotoSerif).expect("serif");
    assert!(
        page_content_streams(&parsed)[0]
            .contains(&format!("<{}> Tj", glyph_hex(&font, "Página 1 de 100"))),
        "a declared capacity must reach the footer"
    );

    // A book that declared no capacity: the line is omitted whole rather than printed as
    // "Página 1 de ", which would be a false statement on a signed instrument.
    let mut without = with_capacity.clone();
    without.page_capacity = None;
    let without_bytes = pdfa::write(&without).expect("write capacity-less footer");
    let without_parsed = Document::load_mem(&without_bytes).expect("parse");
    let furniture: Vec<_> = positioned_text(&page_content_streams(&without_parsed)[0])
        .into_iter()
        .filter(|item| item.artifact)
        .collect();
    assert!(
        furniture.is_empty(),
        "an unresolvable footer must draw nothing, got {furniture:?}"
    );
    // …and the omission must not move the body, because the reserve is policy-derived.
    let with_text: Vec<_> = positioned_text(&page_content_streams(&parsed)[0])
        .into_iter()
        .filter(|item| !item.artifact)
        .collect();
    let without_text: Vec<_> = positioned_text(&page_content_streams(&without_parsed)[0])
        .into_iter()
        .filter(|item| !item.artifact)
        .collect();
    assert_eq!(
        with_text, without_text,
        "body layout must not depend on furniture text"
    );
}

#[test]
fn an_enabled_but_empty_furniture_line_costs_the_body_nothing() {
    let mut empty = dense_body(40);
    empty.document_layout.furniture.footer.enabled = true;
    empty.document_layout.furniture.footer.text = "   ".to_string();
    assert_eq!(
        pdfa::write(&empty).expect("write empty footer"),
        pdfa::write(&dense_body(40)).expect("write plain"),
        "furniture that cannot draw must reserve nothing"
    );
}

#[test]
fn a_malformed_furniture_template_fails_the_render_closed() {
    let mut doc = dense_body(2);
    doc.document_layout.furniture.footer.enabled = true;
    doc.document_layout.furniture.footer.text = "Página {{ pagina }}".to_string();
    let error = pdfa::write(&doc).expect_err("an unknown placeholder must not render");
    assert!(
        error.to_string().contains("unknown placeholder"),
        "diagnostic must name the defect, got {error}"
    );
}

#[test]
fn artifact_text_is_admitted_but_bare_text_is_still_rejected() {
    // Relaxing the gate to admit artifact text must not admit *bare* text: "no untagged real
    // content" is the whole reason the check exists. Exercised directly on synthetic streams,
    // because no byte-level mutation of a real file can leave a `Tj` outside every scope without
    // first unbalancing the scopes — which is a different rejection.
    let check = |content: &str| {
        selfcheck::verify_marked_content_scopes(content.as_bytes(), 0, &|message| {
            crate::DocError::Conformance(message)
        })
    };

    let bare = "BT
/F1 9.00 Tf
56.69 700.00 Td
<0024> Tj
ET
";
    let error = check(bare).expect_err("bare text must still be rejected");
    assert!(
        error.to_string().contains("outside a marked-content scope"),
        "got {error}"
    );

    // Page apparatus: legitimate, and the shape the furniture emitter produces.
    let artifact = format!(
        "/Artifact BMC
{bare}EMC
"
    );
    check(&artifact).expect("artifact text is admitted");

    // Real content: unchanged.
    let tagged = format!(
        "/P << /MCID 0 >> BDC
{bare}EMC
"
    );
    check(&tagged).expect("tagged content is admitted");

    // An artifact that smuggles in an MCID is still a contradiction.
    let unbalanced = format!(
        "/Artifact BMC
{bare}"
    );
    assert!(check(&unbalanced).is_err(), "unclosed scopes stay rejected");
}
