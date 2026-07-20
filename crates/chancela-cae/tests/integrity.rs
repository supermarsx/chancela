//! `CaeCatalog::from_dataset` structural-integrity gate — the validator that protects a *fetched*
//! update from corrupting the catalog. `tests/cache.rs` covers the orphan (unresolvable-parent)
//! branch via a fixture; this file drives the remaining distinct `validate_revision` /
//! `validate_parent` rejection branches directly, by constructing minimal malformed datasets.
//!
//! Each dataset puts the crafted node(s) in `rev4` and leaves `rev3` empty (an empty revision has
//! zero counts and validates cleanly), so a single malformed node is what fails validation.

use chancela_cae::{CaeCatalog, CaeDataset, CaeEntry, CaeError, CaeLevel, CaeRevision};

/// A Rev.4 entry with the given code/level/parent (designation is irrelevant to structure).
fn entry(code: &str, level: CaeLevel, parent: Option<&str>) -> CaeEntry {
    CaeEntry {
        code: code.to_owned(),
        designation: format!("designation for {code}"),
        level,
        revision: CaeRevision::Rev4,
        parent: parent.map(str::to_owned),
    }
}

/// A dataset whose Rev.4 array is `rev4` and whose Rev.3 array is empty.
fn dataset(rev4: Vec<CaeEntry>) -> CaeDataset {
    CaeDataset {
        schema_version: 1,
        generated_at: "2026-07-07T00:00:00Z".to_owned(),
        source_note: "integrity test".to_owned(),
        rev3: Vec::new(),
        rev4,
        provenance: None,
    }
}

fn reject(rev4: Vec<CaeEntry>) -> CaeError {
    CaeCatalog::from_dataset(dataset(rev4)).expect_err("malformed dataset must be rejected")
}

#[test]
fn a_valid_minimal_dataset_is_accepted() {
    // Sanity anchor: a well-formed secção→…→subclasse chain passes, so the rejections below are
    // attributable to the specific defect and not to the harness.
    let ok = CaeCatalog::from_dataset(dataset(vec![
        entry("A", CaeLevel::Seccao, None),
        entry("01", CaeLevel::Divisao, Some("A")),
        entry("011", CaeLevel::Grupo, Some("01")),
        entry("0111", CaeLevel::Classe, Some("011")),
        entry("01111", CaeLevel::Subclasse, Some("0111")),
    ]));
    assert!(ok.is_ok(), "well-formed chain must validate: {ok:?}");
}

#[test]
fn duplicate_code_is_rejected() {
    let err = reject(vec![
        entry("A", CaeLevel::Seccao, None),
        entry("A", CaeLevel::Seccao, None),
    ]);
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    assert!(err.to_string().contains("duplicate"), "got {err}");
}

#[test]
fn entry_tagged_with_the_wrong_revision_is_rejected() {
    // A node carrying `Rev3` sitting in the `rev4` array is a data-integrity error.
    let mut e = entry("A", CaeLevel::Seccao, None);
    e.revision = CaeRevision::Rev3;
    let err = reject(vec![e]);
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    assert!(err.to_string().contains("tagged"), "got {err}");
}

#[test]
fn code_shape_disagreeing_with_declared_level_is_rejected() {
    // "A" is a secção-shaped code but is declared a divisão.
    let err = reject(vec![entry("A", CaeLevel::Divisao, None)]);
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    assert!(err.to_string().contains("shape"), "got {err}");
}

#[test]
fn seccao_with_a_parent_is_rejected() {
    let err = reject(vec![entry("A", CaeLevel::Seccao, Some("Z"))]);
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    assert!(err.to_string().contains("no parent"), "got {err}");
}

#[test]
fn non_seccao_without_a_parent_is_rejected() {
    let err = reject(vec![entry("01", CaeLevel::Divisao, None)]);
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    assert!(err.to_string().contains("has no parent"), "got {err}");
}

#[test]
fn parent_at_the_wrong_level_is_rejected() {
    // Grupo "011" points straight at the secção "A" instead of at a divisão.
    let err = reject(vec![
        entry("A", CaeLevel::Seccao, None),
        entry("011", CaeLevel::Grupo, Some("A")),
    ]);
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    assert!(err.to_string().contains("expected"), "got {err}");
}

#[test]
fn parent_that_is_not_the_code_prefix_is_rejected() {
    // Grupo "011" declares divisão "02" as parent — correct level, but "011" is not under "02".
    let err = reject(vec![
        entry("A", CaeLevel::Seccao, None),
        entry("02", CaeLevel::Divisao, Some("A")),
        entry("011", CaeLevel::Grupo, Some("02")),
    ]);
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    assert!(err.to_string().contains("prefix"), "got {err}");
}
