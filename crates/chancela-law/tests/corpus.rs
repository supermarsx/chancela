//! Corpus shape, scope, round-trip and folded-search tests (the E1a gates besides authenticity).

use chancela_law::{BytesLawSource, DreSource, LawArticle, LawCatalog, LawCorpus, Verification};

/// The full in-scope diploma list (plan t55 §5) is present, and the priority CSC 255/399 slots
/// exist — the manager-remuneration articles the user asked for.
#[test]
fn manifest_loads_full_scope_with_priority_slots() {
    let cat = LawCatalog::embedded();
    for id in [
        "csc",
        "cc",
        "dl-268-94",
        "dl-76-a-2006",
        "cod-cooperativo",
        "lei-24-2012",
        "eidas-910-2014",
        "gdpr-2016-679",
        "eidas2-2024-1183",
    ] {
        assert!(cat.diploma(id).is_some(), "diploma {id} must be seeded");
    }
    assert_eq!(cat.diplomas().len(), 9, "full §5 diploma scope");

    // The user's explicit ask: manager remuneration — CSC 255.º (gerentes) + 399.º (administradores).
    let a255 = cat.article("csc", "255").expect("CSC 255 present");
    assert_eq!(a255.label, "Artigo 255.º");
    assert_eq!(a255.heading, "Remuneração dos gerentes");
    assert!(a255.cross_refs.contains(&"csc:399".to_owned()));
    let a399 = cat.article("csc", "399").expect("CSC 399 present");
    assert_eq!(a399.heading, "Remuneração dos administradores");

    // A suffixed article key round-trips (270-A / 1438-A shape).
    assert!(cat.article("csc", "270-A").is_some());
    assert!(cat.article("cc", "1438-A").is_some());

    // Coverage after t55-E1b-eu: the 3 EU-reg diplomas are fully vendored VERBATIM from EUR-Lex
    // (eIDAS 52 + RGPD 99 + eIDAS2 2 = 153 Verified articles); the 6 DRE-sourced diplomas remain
    // Pending (the JS-gated DRE SPA is not curl-vendorable — see the pilot findings). So:
    //   verified = 153, pending = 40 (DRE seeds), articles = 193.
    let c = cat.metadata().counts;
    assert_eq!(
        c.verified, 153,
        "the 3 EU regs are fully vendored (52 + 99 + 2)"
    );
    assert_eq!(c.pending, 40, "the 6 DRE diplomas stay Pending");
    assert_eq!(c.articles, 193, "total = 153 Verified + 40 Pending");
    assert_eq!(c.verified + c.pending, c.articles);

    // Each EU regulation carries its COMPLETE authentic article set (not the E1a cited seed).
    assert_eq!(cat.articles_for("eidas-910-2014").len(), 52);
    assert_eq!(cat.articles_for("gdpr-2016-679").len(), 99);
    assert_eq!(cat.articles_for("eidas2-2024-1183").len(), 2);
}

/// The label is derived correctly for suffixed and plain numbers.
#[test]
fn article_labels_are_canonical() {
    let cat = LawCatalog::embedded();
    assert_eq!(cat.article("csc", "63").unwrap().label, "Artigo 63.º");
    assert_eq!(cat.article("csc", "270-A").unwrap().label, "Artigo 270.º-A");
    assert_eq!(
        cat.article("cc", "1438-A").unwrap().label,
        "Artigo 1438.º-A"
    );
}

/// Folded (accent+case-insensitive) search finds a seeded **Pending** article by its heading —
/// searching "everything", including bodies once vendored.
#[test]
fn folded_search_finds_pending_article_by_heading() {
    let cat = LawCatalog::embedded();

    // Accent-insensitive: "remuneracao" (no accent) matches the epígrafe "Remuneração dos gerentes".
    let hits = cat.search("remuneracao dos gerentes");
    assert!(
        hits.iter()
            .any(|a| a.diploma_id == "csc" && a.number == "255"),
        "search by heading finds the Pending CSC 255"
    );

    // Case-insensitive by label / diploma context.
    let by_label = cat.search("ARTIGO 399");
    assert!(by_label.iter().any(|a| a.number == "399"));

    // Blank query → no results.
    assert!(cat.search("   ").is_empty());

    // Body search now works over the vendored EU-reg text (contract for E2/E3): a term that only
    // appears inside a Verified article body matches. "pseudonimização" is in RGPD art. 25's body.
    let body_hits = cat.search("pseudonimizacao");
    assert!(
        body_hits
            .iter()
            .any(|a| a.diploma_id == "gdpr-2016-679" && a.number == "25"),
        "accent-folded body search finds the vendored RGPD 25 text"
    );

    // A nonsense term still returns nothing.
    assert!(cat.search("zzz-nao-existe").is_empty());
}

/// The corpus round-trips through JSON (serialize → parse) with no shape drift, and a fetched
/// envelope loads via the `DreSource` trait.
#[test]
fn corpus_round_trips_and_loads_via_source() {
    let cat = LawCatalog::embedded();
    // Reserialize one article and parse it back — the frozen shape is stable.
    let a: &LawArticle = cat.article("csc", "255").unwrap();
    let json = serde_json::to_string(a).unwrap();
    let back: LawArticle = serde_json::from_str(&json).unwrap();
    assert_eq!(a, &back);

    // A full envelope round-trips and loads through the fetch trait.
    let corpus = LawCorpus {
        schema_version: 1,
        generated_at: "2026-07-08T00:00:00Z".to_owned(),
        source_note: "round-trip".to_owned(),
        provenance: None,
        diplomas: cat.diplomas().to_vec(),
    };
    let bytes = serde_json::to_vec(&corpus).unwrap();
    let src = BytesLawSource::new(bytes);
    let fetched = src.fetch().expect("bytes source parses");
    let rebuilt = LawCatalog::from_corpus(fetched).expect("rebuilds + passes the gate");
    assert_eq!(rebuilt.diplomas().len(), 9);
    assert_eq!(rebuilt.metadata().counts, cat.metadata().counts);
    assert!(matches!(
        rebuilt.article("csc", "255").unwrap().verification,
        Verification::Pending
    ));
}
