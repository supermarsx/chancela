//! Lookup / hierarchy / children / search behaviour over the embedded catalog.

use chancela_cae::{CaeCatalog, CaeLevel, CaeRevision};

#[test]
fn lookup_is_case_insensitive_for_seccao_letters() {
    let cat = CaeCatalog::embedded();
    let upper = cat.lookup("A", Some(CaeRevision::Rev4)).unwrap();
    let lower = cat.lookup(" a ", Some(CaeRevision::Rev4)).unwrap();
    assert_eq!(upper.code, "A");
    assert_eq!(lower.code, "A");
    assert_eq!(upper.designation, lower.designation);
}

#[test]
fn lookup_without_revision_prefers_rev4_then_falls_back_to_rev3() {
    let cat = CaeCatalog::embedded();

    // "01" exists in both revisions → Rev.4 wins.
    let both = cat.lookup("01", None).expect("01 in both revisions");
    assert_eq!(both.revision, CaeRevision::Rev4);

    // "56101" (Restaurantes tipo tradicional) exists only in Rev.3 → falls back.
    let only3 = cat.lookup("56101", None).expect("56101 only in Rev.3");
    assert_eq!(only3.revision, CaeRevision::Rev3);
    assert_eq!(only3.designation, "Restaurantes tipo tradicional.");
}

#[test]
fn lookup_unknown_code_returns_none() {
    let cat = CaeCatalog::embedded();
    assert!(cat.lookup("ZZZZZ", None).is_none());
    assert!(cat.lookup("99999", Some(CaeRevision::Rev4)).is_none());
}

#[test]
fn hierarchy_returns_seccao_to_self_inclusive() {
    let cat = CaeCatalog::embedded();
    let chain = cat.hierarchy("68110", CaeRevision::Rev4);
    let codes: Vec<&str> = chain.iter().map(|e| e.code.as_str()).collect();
    assert_eq!(codes, ["M", "68", "681", "6811", "68110"]);
    assert_eq!(chain.first().unwrap().level, CaeLevel::Seccao);
}

#[test]
fn hierarchy_of_unknown_code_is_empty() {
    let cat = CaeCatalog::embedded();
    assert!(cat.hierarchy("00000", CaeRevision::Rev4).is_empty());
}

#[test]
fn children_lists_direct_descendants_only() {
    let cat = CaeCatalog::embedded();
    // Division 68 (Atividades imobiliárias) in Rev.4 has groups 681, 682, 683.
    let kids = cat.children("68", CaeRevision::Rev4);
    let codes: Vec<&str> = kids.iter().map(|e| e.code.as_str()).collect();
    assert_eq!(codes, ["681", "682", "683"]);
    assert!(kids.iter().all(|e| e.level == CaeLevel::Grupo));

    // A leaf subclasse has no children.
    assert!(cat.children("68110", CaeRevision::Rev4).is_empty());
}

#[test]
fn search_is_accent_and_case_folded() {
    let cat = CaeCatalog::embedded();
    // "imobili" (no accents) must match "imobiliários".
    let hits = cat.search("imobili", Some(CaeRevision::Rev4), 50);
    assert!(!hits.is_empty());
    assert!(
        hits.iter().any(|e| e.designation.contains("imobiliári")),
        "search should surface real-estate designations"
    );

    // Folding both sides: querying with accents still matches.
    let accented = cat.search("programação", Some(CaeRevision::Rev4), 10);
    assert!(accented.iter().any(|e| e.code == "62100"));
}

#[test]
fn search_matches_codes_and_respects_limit_and_revision() {
    let cat = CaeCatalog::embedded();

    // Code substring search.
    let by_code = cat.search("6811", Some(CaeRevision::Rev4), 10);
    assert!(by_code.iter().any(|e| e.code == "6811"));
    assert!(by_code.iter().any(|e| e.code == "68110"));

    // Limit is honoured.
    let capped = cat.search("a", Some(CaeRevision::Rev4), 3);
    assert_eq!(capped.len(), 3);

    // Revision filter.
    let only3 = cat.search("Actividades", Some(CaeRevision::Rev3), 5);
    assert!(only3.iter().all(|e| e.revision == CaeRevision::Rev3));

    // Empty query / zero limit → empty.
    assert!(cat.search("", None, 10).is_empty());
    assert!(cat.search("imobili", None, 0).is_empty());
}

#[test]
fn default_equals_embedded() {
    let d = CaeCatalog::default();
    assert_eq!(
        d.metadata().digest,
        CaeCatalog::embedded().metadata().digest
    );
}
