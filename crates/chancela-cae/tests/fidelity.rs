//! The CI **fidelity gate**: proves the embedded catalog is the *complete* official table, not a
//! curated subset. Enforces the exact per-level structural counts of both revisions, that every
//! node chains to a secção, and that a spread of known spot-check codes resolve to their exact
//! official Portuguese designations. If the dataset is ever regenerated incompletely or corrupted,
//! these assertions fail.

use chancela_cae::{
    CaeCatalog, CaeLevel, CaeRevision, EXPECTED_REV3_COUNTS, EXPECTED_REV4_COUNTS, verify_fidelity,
};

/// Official CAE-Rev.4 totals (Decreto-Lei n.º 9/2025): 22/87/287/651/915 = 1962. Asserted against
/// the shared [`EXPECTED_REV4_COUNTS`] consts the obtainer's fidelity gate also uses (single source
/// of truth), so the embedded dataset and any obtained dataset are held to the same official totals.
#[test]
fn rev4_structural_counts_match_official_totals() {
    let c = CaeCatalog::embedded().metadata().counts.rev4;
    assert_eq!(c, EXPECTED_REV4_COUNTS, "Rev.4 per-level counts");
    assert_eq!(c.seccao, 22, "Rev.4 secções");
    assert_eq!(c.divisao, 87, "Rev.4 divisões");
    assert_eq!(c.grupo, 287, "Rev.4 grupos");
    assert_eq!(c.classe, 651, "Rev.4 classes");
    assert_eq!(c.subclasse, 915, "Rev.4 subclasses");
    assert_eq!(c.total(), 1962, "Rev.4 total nodes");
}

/// CAE-Rev.3 totals derived from the primary legal source (Decreto-Lei n.º 381/2007):
/// 21/88/272/616/850 = 1847. The class count 616 is corroborated by INE (NACE-Rev.2's 615 + 1).
#[test]
fn rev3_structural_counts_match_primary_source() {
    let c = CaeCatalog::embedded().metadata().counts.rev3;
    assert_eq!(c, EXPECTED_REV3_COUNTS, "Rev.3 per-level counts");
    assert_eq!(c.seccao, 21, "Rev.3 secções");
    assert_eq!(c.divisao, 88, "Rev.3 divisões");
    assert_eq!(c.grupo, 272, "Rev.3 grupos");
    assert_eq!(c.classe, 616, "Rev.3 classes");
    assert_eq!(c.subclasse, 850, "Rev.3 subclasses");
    assert_eq!(c.total(), 1847, "Rev.3 total nodes");
}

/// The embedded catalog passes the obtainer's full-count fidelity gate — the same gate an obtained
/// dataset must pass before it may supersede the active catalog.
#[test]
fn embedded_passes_fidelity_gate() {
    verify_fidelity(&CaeCatalog::embedded().metadata().counts).expect("embedded passes fidelity");
}

/// Every non-secção node must chain, via `parent`, up to a secção — asserted here across the whole
/// catalog (the embedded build already enforces this, but this makes the guarantee explicit).
#[test]
fn every_node_chains_to_a_seccao() {
    let cat = CaeCatalog::embedded();
    for rev in [CaeRevision::Rev3, CaeRevision::Rev4] {
        // Walk from a representative deepest node in each revision and assert a 5-long chain.
        let deep = if rev == CaeRevision::Rev4 {
            "68110"
        } else {
            "68100"
        };
        let chain = cat.hierarchy(deep, rev);
        assert_eq!(chain.len(), 5, "{rev:?} {deep} full depth");
        assert_eq!(
            chain[0].level,
            CaeLevel::Seccao,
            "{rev:?} chain starts at a secção"
        );
        assert_eq!(
            chain[4].code, deep,
            "{rev:?} chain ends at the queried code"
        );
        // Consecutive levels increase by exactly one step.
        let levels: Vec<CaeLevel> = chain.iter().map(|e| e.level).collect();
        assert_eq!(
            levels,
            vec![
                CaeLevel::Seccao,
                CaeLevel::Divisao,
                CaeLevel::Grupo,
                CaeLevel::Classe,
                CaeLevel::Subclasse
            ],
            "{rev:?} chain levels"
        );
    }
}

fn assert_spot(rev: CaeRevision, code: &str, level: CaeLevel, designation: &str) {
    let cat = CaeCatalog::embedded();
    let e = cat
        .lookup(code, Some(rev))
        .unwrap_or_else(|| panic!("{rev:?} {code} must resolve"));
    assert_eq!(e.level, level, "{rev:?} {code} level");
    assert_eq!(e.designation, designation, "{rev:?} {code} designation");
    assert_eq!(e.revision, rev, "{rev:?} {code} revision tag");
}

/// ~15 known spot-check codes resolving to their exact official designations (both revisions,
/// every level). These transcriptions are the anchor against silent extraction drift.
#[test]
fn spot_check_designations_rev4() {
    use CaeLevel::*;
    use CaeRevision::Rev4;
    assert_spot(Rev4, "A", Seccao, "Agricultura, floresta e pesca.");
    assert_spot(Rev4, "B", Seccao, "Indústrias extrativas.");
    assert_spot(
        Rev4,
        "V",
        Seccao,
        "Atividades dos organismos internacionais e outras instituições extraterritoriais.",
    );
    assert_spot(Rev4, "68", Divisao, "Atividades imobiliárias.");
    assert_spot(
        Rev4,
        "681",
        Grupo,
        "Atividades imobiliárias com bens imobiliários próprios e desenvolvimento de projetos de edifícios.",
    );
    assert_spot(Rev4, "6811", Classe, "Compra e venda de bens imobiliários.");
    assert_spot(
        Rev4,
        "68110",
        Subclasse,
        "Compra e venda de bens imobiliários.",
    );
    assert_spot(
        Rev4,
        "68200",
        Subclasse,
        "Arrendamento e exploração de bens imobiliários próprios ou em locação.",
    );
    assert_spot(
        Rev4,
        "41000",
        Subclasse,
        "Construção de edifícios residenciais e não residenciais.",
    );
    assert_spot(
        Rev4,
        "62100",
        Subclasse,
        "Atividades de programação informática.",
    );
    assert_spot(
        Rev4,
        "47300",
        Subclasse,
        "Comércio a retalho de combustível para veículos a motor.",
    );
}

#[test]
fn spot_check_designations_rev3() {
    use CaeLevel::*;
    use CaeRevision::Rev3;
    assert_spot(
        Rev3,
        "A",
        Seccao,
        "Agricultura, produção animal, caça, floresta e pesca.",
    );
    assert_spot(Rev3, "L", Seccao, "Actividades imobiliárias.");
    assert_spot(Rev3, "68", Divisao, "Actividades imobiliárias.");
    assert_spot(Rev3, "6810", Classe, "Compra e venda de bens imobiliários.");
    assert_spot(
        Rev3,
        "68100",
        Subclasse,
        "Compra e venda de bens imobiliários.",
    );
    assert_spot(
        Rev3,
        "41200",
        Subclasse,
        "Construção de edifícios (residenciais e não residenciais).",
    );
    assert_spot(
        Rev3,
        "62010",
        Subclasse,
        "Actividades de programação informática.",
    );
    assert_spot(Rev3, "56101", Subclasse, "Restaurantes tipo tradicional.");
    assert_spot(Rev3, "01111", Subclasse, "Cerealicultura (excepto arroz).");
}

/// Group 843 is the single reconstructed node (DL 381/2007 omits its printed header row); assert it
/// is present, correctly placed, and shares its sole child's designation.
#[test]
fn rev3_reconstructed_group_843_present() {
    let cat = CaeCatalog::embedded();
    let g = cat
        .lookup("843", Some(CaeRevision::Rev3))
        .expect("group 843");
    assert_eq!(g.level, CaeLevel::Grupo);
    assert_eq!(g.parent.as_deref(), Some("84"));
    let child = cat
        .lookup("8430", Some(CaeRevision::Rev3))
        .expect("class 8430");
    assert_eq!(g.designation, child.designation);
}
