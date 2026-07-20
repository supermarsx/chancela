//! The **fidelity gate** for the EU-regulation diplomas vendored VERBATIM from EUR-Lex (t55-E1b-eu).
//!
//! These prove the embedded corpus carries the *complete, authentic* OJ article set of each EU
//! regulation — not a curated subset, not paraphrase. They spot-check known epígrafes + the exact
//! opening words of well-known articles, assert the full article counts, and confirm every EU-reg
//! article is `Verified` with a complete source pinned to the vendored artifact's sha256. If the
//! dataset is ever regenerated incompletely, corrupted, or an article's text drifts, these fail.

use chancela_law::LawCatalog;

/// The three EU regulations carry their COMPLETE OJ article set: eIDAS 52, RGPD 99, eIDAS2 2.
#[test]
fn eu_regulations_have_complete_article_sets() {
    let cat = LawCatalog::embedded();
    assert_eq!(
        cat.articles_for("eidas-910-2014").len(),
        52,
        "eIDAS arts 1–52"
    );
    assert_eq!(
        cat.articles_for("gdpr-2016-679").len(),
        99,
        "RGPD arts 1–99"
    );
    assert_eq!(
        cat.articles_for("eidas2-2024-1183").len(),
        2,
        "eIDAS2 arts 1–2"
    );

    // Contiguous 1..=N (the source, not an invented range, is the authority).
    for (id, n) in [
        ("eidas-910-2014", 52u32),
        ("gdpr-2016-679", 99),
        ("eidas2-2024-1183", 2),
    ] {
        for i in 1..=n {
            assert!(
                cat.article(id, &i.to_string()).is_some(),
                "{id} must have Artigo {i}.º"
            );
        }
    }
}

/// Every EU-reg article is `Verified` with a complete source pinned to the vendored artifact digest.
#[test]
fn every_eu_reg_article_is_verified_and_sourced() {
    let cat = LawCatalog::embedded();
    let expected_digest = [
        (
            "eidas-910-2014",
            "bf56872ea8cea5da4af290a3418ae65804491d9f86092a6fe4d8fc93b2e5889f",
        ),
        (
            "gdpr-2016-679",
            "b27b27f500866926adcb775f2ac115eb075fc2ab8f7985101ea0fe5c68937c23",
        ),
        (
            "eidas2-2024-1183",
            "4c5bef3e6149a679888869e856ebe3728ae6cc3aff70b01e81f5d0c5bfc9eabf",
        ),
    ];
    for (id, digest) in expected_digest {
        for a in cat.articles_for(id) {
            assert!(a.is_verified(), "{id}:{} must be Verified", a.number);
            assert!(
                a.source.is_complete(),
                "{id}:{} needs a complete source",
                a.number
            );
            assert!(
                !a.body.trim().is_empty(),
                "{id}:{} body must be non-empty",
                a.number
            );
            assert_eq!(
                a.source.source_digest.as_deref(),
                Some(digest),
                "{id}:{} pinned to the vendored artifact sha256",
                a.number
            );
            assert!(
                a.source
                    .url
                    .as_deref()
                    .is_some_and(|u| u.contains("eur-lex.europa.eu")),
                "{id}:{} cites EUR-Lex",
                a.number
            );
        }
    }
}

/// Verbatim spot-checks: known epígrafes + exact opening words of signature/data-protection articles.
#[test]
fn eu_reg_spot_checks_are_verbatim() {
    let cat = LawCatalog::embedded();

    // eIDAS art. 25 — the signature-relevant core (legal effect of electronic signatures).
    let a = cat.article("eidas-910-2014", "25").expect("eIDAS 25");
    assert_eq!(a.heading, "Efeitos legais das assinaturas eletrónicas");
    assert!(
        a.body.contains("A assinatura eletrónica qualificada tem um efeito legal equivalente ao de uma assinatura manuscrita."),
        "eIDAS 25(2) verbatim"
    );

    // eIDAS art. 3 — the definitions article opens with «assinatura eletrónica».
    let a3 = cat.article("eidas-910-2014", "3").expect("eIDAS 3");
    assert_eq!(a3.heading, "Definições");

    // RGPD art. 5 — the data-protection principles.
    let a5 = cat.article("gdpr-2016-679", "5").expect("RGPD 5");
    assert_eq!(
        a5.heading,
        "Princípios relativos ao tratamento de dados pessoais"
    );
    assert!(
        a5.body.contains("licitude, lealdade e transparência"),
        "RGPD 5 verbatim principle"
    );

    // RGPD art. 25 — data protection by design and by default.
    let a25 = cat.article("gdpr-2016-679", "25").expect("RGPD 25");
    assert_eq!(
        a25.heading,
        "Proteção de dados desde a conceção e por defeito"
    );
    assert!(a25.body.contains("pseudonimização"), "RGPD 25 verbatim");

    // eIDAS2 art. 1 — the amending clause opening.
    let e2 = cat.article("eidas2-2024-1183", "1").expect("eIDAS2 1");
    assert_eq!(e2.heading, "Alteração do Regulamento (UE) n.º 910/2014");
    assert!(
        e2.body
            .starts_with("O Regulamento (UE) n.º 910/2014 é alterado do seguinte modo:"),
        "eIDAS2 1 verbatim opening"
    );
}
