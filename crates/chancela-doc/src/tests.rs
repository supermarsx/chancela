//! Unit tests for the PDF/A-2u writer (structural self-check, determinism, pagination, and the
//! diacritic `/ToUnicode` round-trip). The generate→pades-sign round-trip lives in `tests/` and is
//! owned by e3.
//!
//! Fixtures use the fictional "Encosto Estratégico Lda" / "Amélia Marques" — never a real entity.

use chancela_core::{Block, DocumentModel, KvRow, Run, SignatureSlot, VoteRow};
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
    assert_diagnostic(&err, "the writer emits a single Type0");
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
