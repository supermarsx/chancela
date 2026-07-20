//! Multi-format JSON obtain (plan t23 §2.2–2.3): the Simple-JSON mirror parser (with level/parent
//! derivation) and format auto-detection, all offline. The full-fidelity cases round-trip the real
//! vendored dataset through each JSON format, proving a mirror reproduces the official table.

use std::path::{Path, PathBuf};

use chancela_cae::{
    CaeCatalog, CaeDataset, CaeError, CaeSourceFormat, DrPdfSource, EXPECTED_REV3_COUNTS,
    EXPECTED_REV4_COUNTS, OfficialCaeSource, detect_format, parse_artifact, verify_fidelity,
};

fn vendored(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data/source")
        .join(name)
}

/// The full official dataset from the committed DR PDFs (the in-app parser output).
fn vendored_dataset() -> CaeDataset {
    DrPdfSource::from_files(&vendored("rev4.pdf"), &vendored("rev3.pdf"))
        .obtain()
        .expect("obtain parses the vendored diploma PDFs")
        .dataset
}

/// Serialize a dataset as a Simple-JSON mirror array **without** `level`/`parent` (forcing full
/// derivation on parse). Rev.4 block then Rev.3 block, each in canonical (secção-first) order.
fn simple_json_derivable(ds: &CaeDataset) -> Vec<u8> {
    let arr: Vec<serde_json::Value> = ds
        .rev4
        .iter()
        .chain(ds.rev3.iter())
        .map(|e| {
            serde_json::json!({
                "code": e.code,
                "designation": e.designation,
                "revision": e.revision,
            })
        })
        .collect();
    serde_json::to_vec(&arr).expect("serialize simple-json array")
}

/// THE Simple-JSON fidelity cross-check: the full official table hosted as a flat array with every
/// `level`/`parent` OMITTED still reconstructs byte-identically (levels + parents derived exactly as
/// the generator does) and passes structural integrity + full-count fidelity.
#[test]
fn simple_json_full_table_derives_and_passes_the_gates() {
    let ds = vendored_dataset();
    let bytes = simple_json_derivable(&ds);

    let parsed = parse_artifact(&bytes, CaeSourceFormat::SimpleJson).expect("simple-json parses");

    // Derivation reconstructs level + parent for every node, identical to the source dataset.
    assert_eq!(parsed.rev4, ds.rev4, "Rev.4 entries reconstructed verbatim");
    assert_eq!(parsed.rev3, ds.rev3, "Rev.3 entries reconstructed verbatim");

    // Same gates as every other format.
    let catalog = CaeCatalog::from_dataset(parsed).expect("derived dataset passes integrity");
    verify_fidelity(&catalog.metadata().counts).expect("derived dataset passes fidelity");
    assert_eq!(catalog.metadata().counts.rev4, EXPECTED_REV4_COUNTS);
    assert_eq!(catalog.metadata().counts.rev3, EXPECTED_REV3_COUNTS);
}

/// A structurally-valid but SHORT simple-json array (dropping leaf subclasses) parses fine but is
/// caught by the fidelity gate — it can never masquerade as the full catalog.
#[test]
fn short_simple_json_fails_fidelity() {
    let mut ds = vendored_dataset();
    let mut dropped = 0;
    ds.rev4.retain(|e| {
        if dropped < 5 && e.level == chancela_cae::CaeLevel::Subclasse {
            dropped += 1;
            false
        } else {
            true
        }
    });
    let bytes = simple_json_derivable(&ds);

    let parsed = parse_artifact(&bytes, CaeSourceFormat::SimpleJson).expect("parses");
    // Structural integrity still holds (leaves have no children) — only fidelity catches the shortfall.
    let catalog = CaeCatalog::from_dataset(parsed).expect("short array is structurally valid");
    let err = verify_fidelity(&catalog.metadata().counts).expect_err("short array fails fidelity");
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
}

/// A level declared on a node that contradicts its code shape is rejected by structural integrity.
#[test]
fn simple_json_level_mismatch_is_rejected() {
    // "68" is a two-digit divisão by shape; declaring it a secção is an integrity failure.
    let bytes = br#"[
        {"code":"A","designation":"Sec.","revision":"Rev4","level":"Seccao","parent":null},
        {"code":"68","designation":"Wrong.","revision":"Rev4","level":"Seccao","parent":null}
    ]"#;
    let parsed =
        parse_artifact(bytes, CaeSourceFormat::SimpleJson).expect("parses (JSON is valid)");
    let err = CaeCatalog::from_dataset(parsed).expect_err("level mismatch fails integrity");
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
}

/// A node whose derived/explicit parent does not resolve (an orphan) is rejected by integrity.
#[test]
fn simple_json_orphan_parent_is_rejected() {
    // Divisão 68 with an explicit parent "Z" that is not in the array → unresolved parent.
    let bytes = br#"[
        {"code":"68","designation":"Orphan.","revision":"Rev4","level":"Divisao","parent":"Z"}
    ]"#;
    let parsed = parse_artifact(bytes, CaeSourceFormat::SimpleJson).expect("parses");
    let err = CaeCatalog::from_dataset(parsed).expect_err("orphan parent fails integrity");
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
}

// --- Format auto-detection (plan t23 §2.2) ---

#[test]
fn auto_detect_routes_all_three_branches() {
    assert_eq!(detect_format(b"%PDF-1.7"), Some(CaeSourceFormat::Pdf));
    assert_eq!(
        detect_format(b"  {\"rev4\":[]}"),
        Some(CaeSourceFormat::Envelope)
    );
    assert_eq!(
        detect_format(b"\n[{\"code\":\"A\"}]"),
        Some(CaeSourceFormat::SimpleJson)
    );
    assert_eq!(detect_format(b"garbage"), None);
}

/// Auto-detect parses a real envelope (the vendored dataset, serialized) through the full gates.
#[test]
fn auto_detect_parses_a_real_envelope() {
    let ds = vendored_dataset();
    let bytes = serde_json::to_vec(&ds).expect("serialize envelope");

    // Sniffed as an object → Envelope → full dataset.
    assert_eq!(detect_format(&bytes), Some(CaeSourceFormat::Envelope));
    let parsed =
        parse_artifact(&bytes, CaeSourceFormat::Auto).expect("auto-detect parses envelope");
    let catalog = CaeCatalog::from_dataset(parsed).expect("integrity");
    verify_fidelity(&catalog.metadata().counts).expect("envelope full");
}

/// Auto-detect parses a real Simple-JSON mirror (the vendored dataset as a flat array).
#[test]
fn auto_detect_parses_a_real_simple_json() {
    let ds = vendored_dataset();
    let bytes = simple_json_derivable(&ds);

    assert_eq!(detect_format(&bytes), Some(CaeSourceFormat::SimpleJson));
    let parsed =
        parse_artifact(&bytes, CaeSourceFormat::Auto).expect("auto-detect parses simple-json");
    let catalog = CaeCatalog::from_dataset(parsed).expect("integrity");
    verify_fidelity(&catalog.metadata().counts).expect("simple-json full");
}

/// A `%PDF` artifact on the auto-detect/mirror path is a clear, rejecting Parse error (the DR pair is
/// obtained via the dedicated official source, not a single mirror URL).
#[test]
fn auto_detect_rejects_pdf_on_the_mirror_path() {
    let err =
        parse_artifact(b"%PDF-1.7\nfoo", CaeSourceFormat::Auto).expect_err("PDF is not a mirror");
    assert!(matches!(err, CaeError::Parse(_)), "got {err:?}");
}

/// Malformed / unrecognised bytes are a clear Parse error.
#[test]
fn auto_detect_rejects_malformed_bytes() {
    let err = parse_artifact(b"not an artifact at all", CaeSourceFormat::Auto)
        .expect_err("garbage rejected");
    assert!(matches!(err, CaeError::Parse(_)), "got {err:?}");
}
