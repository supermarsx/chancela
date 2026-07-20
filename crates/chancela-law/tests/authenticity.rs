//! The authenticity HARD GATE (the whole point of the crate) + the Pending-marker contract.
//!
//! These prove that no article can present un-sourced text as law: a `Verified` article MUST carry
//! a complete `LawSource`, and a `Pending` article renders the loud marker, never a (never-written)
//! body. The gate is enforced both at corpus-build time (`LawCatalog::from_corpus`) and here.

use chancela_law::{
    DiplomaKind, LawArticle, LawCatalog, LawCorpus, LawDiploma, LawSource, UNVERIFIED_MARKER,
    Verification,
};

/// Every `Verified` article in the embedded corpus has a complete source. With the E1a skeleton
/// everything is `Pending`, so this holds vacuously — and stays true as E1b flips articles, because
/// the corpus build would reject any `Verified`-without-source before it reaches here.
#[test]
fn no_verified_article_without_complete_source() {
    let cat = LawCatalog::embedded();
    for d in cat.diplomas() {
        for a in &d.articles {
            if a.is_verified() {
                assert!(
                    a.source.is_complete(),
                    "{}:{} is Verified but its source is incomplete",
                    d.id,
                    a.number
                );
                assert!(
                    !a.body.trim().is_empty(),
                    "{}:{} is Verified but its body is empty",
                    d.id,
                    a.number
                );
            }
        }
    }
}

/// A `Pending` article renders the loud marker in place of body text — never its raw body.
/// A body-bearing article (`Verified` or `AutomatedReview`) renders its real text instead.
#[test]
fn pending_article_renders_the_marker() {
    let cat = LawCatalog::embedded();
    assert_eq!(UNVERIFIED_MARKER, "[NÃO VERIFICADO / fonte pendente]");

    // dl-76-a-2006 art. 2 is the one article left Pending (see corpus.rs) — it renders the marker.
    let pending = cat
        .article("dl-76-a-2006", "2")
        .expect("dl-76-a-2006 art. 2 seeded");
    assert!(!pending.has_body_text(), "art. 2 stays Pending");
    assert_eq!(pending.display_body(), UNVERIFIED_MARKER);

    // CSC 255 is now automated-review vendored: it renders its real body, NOT the marker — but it
    // is still NOT human-`Verified` (no human approval was manufactured).
    let art255 = cat.article("csc", "255").expect("CSC 255 seeded");
    assert!(art255.is_automated_review());
    assert!(!art255.is_verified());
    assert_ne!(art255.display_body(), UNVERIFIED_MARKER);
    assert_eq!(art255.display_body(), art255.body);

    // Every article displays the marker IFF it is Pending; body-bearing articles never do.
    for d in cat.diplomas() {
        for a in &d.articles {
            if a.has_body_text() {
                assert_ne!(a.display_body(), UNVERIFIED_MARKER, "{}:{}", d.id, a.number);
            } else {
                assert_eq!(a.display_body(), UNVERIFIED_MARKER, "{}:{}", d.id, a.number);
            }
        }
    }
}

/// The AutomatedReview tier: real vendored text with a complete source and the honest automated
/// caveat, round-tripping through serde — and crucially it is NOT presented as human-`Verified`.
#[test]
fn automated_review_articles_are_sourced_and_honestly_labelled() {
    let cat = LawCatalog::embedded();
    let mut seen = 0u32;
    for d in cat.diplomas() {
        for a in &d.articles {
            if !a.is_automated_review() {
                continue;
            }
            seen += 1;
            // Weaker claim than Verified: never human-approved.
            assert!(
                !a.is_verified(),
                "{}:{} must not read as Verified",
                d.id,
                a.number
            );
            // But still authentic: complete source + non-empty body.
            assert!(
                a.source.is_complete(),
                "{}:{} needs a complete source",
                d.id,
                a.number
            );
            assert!(
                !a.body.trim().is_empty(),
                "{}:{} body must be non-empty",
                d.id,
                a.number
            );
            // The honest provenance caveat is recorded on the source.
            assert_eq!(a.source.review_method.as_deref(), Some("automated-capture"));
            let note = a.source.review_note.as_deref().unwrap_or_default();
            assert!(
                note.contains("NÃO aprovado juridicamente")
                    && note.contains("revisão jurídica humana"),
                "{}:{} must carry the not-human-approved caveat",
                d.id,
                a.number
            );

            // Serde round-trip of the tier + fields is stable.
            let json = serde_json::to_string(a).unwrap();
            assert!(json.contains("\"automated_review\""));
            let back: LawArticle = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, a);
            assert_eq!(back.verification, Verification::AutomatedReview);
        }
    }
    assert_eq!(seen, 39, "39 articles are automated-review vendored");
}

/// The corpus build REJECTS a `Verified` article whose source is incomplete — the gate is a build
/// invariant, not just a lint. (Constructs an in-memory corpus; does not touch the embedded data.)
#[test]
fn build_rejects_verified_without_source() {
    let bad = LawCorpus {
        schema_version: 1,
        generated_at: "2026-07-08T00:00:00Z".to_owned(),
        source_note: "test".to_owned(),
        provenance: None,
        diplomas: vec![LawDiploma {
            id: "csc".to_owned(),
            kind: DiplomaKind::Codigo,
            number: "262/86".to_owned(),
            title: "Código das Sociedades Comerciais".to_owned(),
            reference: "Decreto-Lei n.º 262/86".to_owned(),
            official_url: "https://example.invalid".to_owned(),
            eli: None,
            articles: vec![LawArticle {
                diploma_id: "csc".to_owned(),
                number: "255".to_owned(),
                label: "Artigo 255.º".to_owned(),
                heading: "Remuneração dos gerentes".to_owned(),
                // A fabricated-looking body flagged Verified but WITHOUT a complete source.
                body: "texto inventado".to_owned(),
                source: LawSource::pending("Decreto-Lei n.º 262/86", "Artigo 255.º"),
                verification: Verification::Verified,
                cross_refs: vec![],
            }],
        }],
    };
    let err = LawCatalog::from_corpus(bad).expect_err("must reject Verified-without-source");
    assert!(
        err.to_string().contains("Verified"),
        "unexpected error: {err}"
    );
}

/// A `Verified` article WITH a complete source and body is accepted — proving the gate admits
/// authentic text (what E1b produces), not merely rejects everything.
#[test]
fn build_accepts_verified_with_complete_source() {
    let source = LawSource {
        diploma: "Decreto-Lei n.º 262/86, de 2 de setembro".to_owned(),
        article: "Artigo 255.º".to_owned(),
        dr_reference: Some("DR 1.ª série N.º 201, 02-09-1986".to_owned()),
        dr_date: Some("1986-09-02".to_owned()),
        url: Some("https://data.dre.pt/eli/dec-lei/262/1986/p/cons/20260101".to_owned()),
        source_digest: None,
        retrieved_at: None,
        review_method: None,
        review_note: None,
    };
    assert!(source.is_complete());
    let good = LawCorpus {
        schema_version: 1,
        generated_at: "2026-07-08T00:00:00Z".to_owned(),
        source_note: "test".to_owned(),
        provenance: None,
        diplomas: vec![LawDiploma {
            id: "csc".to_owned(),
            kind: DiplomaKind::Codigo,
            number: "262/86".to_owned(),
            title: "Código das Sociedades Comerciais".to_owned(),
            reference: "Decreto-Lei n.º 262/86".to_owned(),
            official_url: "https://example.invalid".to_owned(),
            eli: None,
            articles: vec![LawArticle {
                diploma_id: "csc".to_owned(),
                number: "255".to_owned(),
                label: "Artigo 255.º".to_owned(),
                heading: "Remuneração dos gerentes".to_owned(),
                // Illustrative placeholder standing in for E1b's vendored verbatim text — the
                // gate checks the SOURCE is complete, not the wording. (Fictional context only.)
                body: "1 - (texto verbatim vendido pelo E1b).".to_owned(),
                source,
                verification: Verification::Verified,
                cross_refs: vec![],
            }],
        }],
    };
    let cat = LawCatalog::from_corpus(good).expect("Verified-with-source is accepted");
    assert_eq!(cat.metadata().counts.verified, 1);
    let a = cat.article("csc", "255").unwrap();
    assert!(a.is_verified());
    assert_eq!(a.display_body(), a.body); // Verified → renders the real body, not the marker.
}
