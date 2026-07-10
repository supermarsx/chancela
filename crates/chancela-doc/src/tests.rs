//! Unit tests for the PDF/A-2u writer (structural self-check, determinism, pagination, and the
//! diacritic `/ToUnicode` round-trip). The generate→pades-sign round-trip lives in `tests/` and is
//! owned by e3.
//!
//! Fixtures use the fictional "Encosto Estratégico Lda" / "Amélia Marques" — never a real entity.

use chancela_core::{Block, DocumentModel, KvRow, Run, SignatureSlot, VoteRow};
use lopdf::{Dictionary, Document, Object};

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
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::KeyValueTablesNotTaggedAsTables)
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
    assert!(!report.pdf_ua_claimed);
    assert!(report.heading_hierarchy.document_title_tagged_as_h1);
    assert_eq!(report.heading_hierarchy.heading_count, 2);
    assert!(report.heading_hierarchy.no_skipped_levels);
    assert!(report.heading_hierarchy.unsupported_levels.is_empty());
    assert!(report.role_map.complete);
    assert!(report.role_map.missing_custom_roles.is_empty());
    assert_eq!(report.table_semantics.key_value_table_count, 1);
    assert_eq!(report.table_semantics.vote_table_count, 1);
    assert!(!report.table_semantics.complete);
    assert_eq!(report.artifact_marking.known_layout_artifact_count, 6);
    assert_eq!(
        report.non_text_content.missing_decorative_artifacts,
        vec!["block:5".to_string()]
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::NoAltTextModel)
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::KeyValueTablesNotTaggedAsTables)
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::VoteTablesNotTaggedAsTables)
    );
    assert!(
        report
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
    assert_eq!(report.table_semantics.key_value_table_count, 1);
    assert_eq!(report.table_semantics.vote_table_count, 1);
    assert!(!report.table_semantics.key_value_tables_have_table_semantics);
    assert!(!report.table_semantics.vote_tables_have_table_semantics);
    assert!(!report.table_semantics.vote_table_headers_tagged);
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::KeyValueTablesNotTaggedAsTables)
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::VoteTablesNotTaggedAsTables)
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::VoteTableHeadersNotTagged)
    );
}

#[test]
fn accessibility_report_records_space_emission_without_pdfua_claim() {
    let report = pdfa::accessibility_report(&fixture());

    assert!(report.inter_word_spaces_emitted);
    assert!(!report.pdf_ua_claimed);
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::KeyValueTablesNotTaggedAsTables)
    );

    let json = report.to_json();
    assert!(json.contains("\"version\":4"));
    assert!(json.contains("\"inter_word_spaces_emitted\":true"));
    assert!(json.contains("\"pdf_ua_claimed\":false"));
}

#[test]
fn accessibility_explicit_alt_text_decorative_model_clears_local_blockers_without_pdfua_claim() {
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
        decorative_artifacts: vec![pdfa::DecorativeArtifact::block(1)],
    };

    let report = pdfa::accessibility_report(
        pdfa::AccessibilityInput::new(&doc).with_alt_text_model(&alt_text_model),
    );

    assert!(report.alt_text_model_present);
    assert!(report.non_text_content.complete);
    assert!(!report.pdf_ua_claimed);
    assert!(report.pdf_ua_blockers.is_empty());
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
fn accessibility_non_text_accounting_reports_missing_and_invalid_entries() {
    let mut doc = DocumentModel::new("Decorativos", "Encosto Estratégico Lda", "Teste");
    doc.blocks = vec![Block::Rule, Block::PageBreak];
    let alt_text_model = pdfa::AltTextModel {
        all_non_text_content_accounted_for: true,
        text_alternatives: vec![pdfa::TextAlternative::new("asset:seal", " ")],
        decorative_artifacts: vec![
            pdfa::DecorativeArtifact::block(0),
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
    assert_eq!(
        report.non_text_content.missing_decorative_artifacts,
        vec!["block:1".to_string()]
    );
    assert_eq!(report.non_text_content.invalid_text_alternative_count, 1);
    assert_eq!(report.non_text_content.invalid_decorative_artifact_count, 1);
    assert!(!report.non_text_content.complete);
    assert_eq!(
        report.pdf_ua_blockers,
        vec![pdfa::PdfUaBlocker::NonTextContentNotAccountedFor]
    );
}

#[test]
fn accessibility_report_json_is_deterministic() {
    let a = pdfa::accessibility_report(&fixture()).to_json();
    let b = pdfa::accessibility_report(&fixture()).to_json();
    assert_eq!(a, b);
    assert_eq!(
        a,
        "{\"version\":4,\"pdf_ua_claimed\":false,\"metadata\":{\"title\":{\"value\":\"Ata da Assembleia Geral\",\"source_present\":true,\"fallback_used\":false},\"language\":{\"value\":\"pt-PT\",\"source_present\":true,\"fallback_used\":false},\"catalog_lang\":true,\"display_doc_title\":true,\"xmp_title\":true,\"xmp_language\":true},\"text\":{\"embedded_fonts\":true,\"to_unicode_cmaps\":true,\"inter_word_spaces_emitted\":true},\"reading_order\":{\"content_streams_follow_model_order\":true,\"structure_tree_present\":true,\"tagged_content_present\":true,\"layout_artifacts_marked\":true,\"pages_use_structure_tab_order\":true},\"tagged_structure\":{\"heading_hierarchy\":{\"document_title_tagged_as_h1\":true,\"heading_count\":2,\"max_observed_level\":2,\"no_skipped_levels\":true,\"unsupported_levels\":[]},\"role_map\":{\"present\":true,\"required_custom_roles\":[\"ChancelaDocument\",\"ChancelaDocumentTitle\",\"ChancelaHeaderMetadata\",\"ChancelaHeading1\",\"ChancelaHeading2\",\"ChancelaParagraph\",\"ChancelaKeyValue\",\"ChancelaVoteTable\",\"ChancelaSignatureBlock\"],\"missing_custom_roles\":[],\"standard_targets_only\":true,\"complete\":true},\"tables\":{\"key_value_table_count\":1,\"vote_table_count\":1,\"key_value_tables_have_table_semantics\":false,\"vote_tables_have_table_semantics\":false,\"vote_table_headers_tagged\":false,\"complete\":false},\"artifact_marking\":{\"layout_artifacts_marked\":true,\"known_layout_artifact_count\":6,\"header_rule_artifact_count\":1,\"horizontal_rule_artifact_count\":1,\"vote_table_rule_artifact_count\":2,\"signature_line_artifact_count\":2}},\"non_text_content\":{\"model_supplied\":false,\"all_non_text_content_accounted_for\":false,\"text_alternative_count\":0,\"decorative_artifact_count\":0,\"known_decorative_block_count\":1,\"missing_decorative_artifacts\":[\"block:5\"],\"invalid_text_alternative_count\":0,\"invalid_decorative_artifact_count\":0,\"complete\":false},\"alt_text_model_present\":false,\"pdf_ua_blockers\":[\"key_value_tables_not_tagged_as_tables\",\"vote_tables_not_tagged_as_tables\",\"vote_table_headers_not_tagged\",\"no_alt_text_model\"]}"
    );
}

#[test]
fn pdf_ua_is_not_claimed_with_minimal_tagging() {
    let report = pdfa::accessibility_report(&fixture());
    assert!(!report.pdf_ua_claimed);
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
        report
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
        !bytes.windows(7).any(|w| w == b"pdfuaid"),
        "writer must not emit PDF/UA identification metadata"
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
