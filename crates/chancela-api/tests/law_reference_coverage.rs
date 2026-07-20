use chancela_law::{LawCatalog, LawDiploma, UNVERIFIED_MARKER, Verification};
use chancela_templates::{
    LEGAL_THRESHOLDS, TemplateLawReferenceSource, TemplateLawReferenceVerification, find_threshold,
    load_registry,
};

#[derive(Debug)]
struct LawReferenceAuditRow {
    template_id: String,
    source_id: String,
    article: Option<String>,
    reference_source: &'static str,
    threshold_id: Option<String>,
    corpus_status: Option<&'static str>,
    resolved: bool,
    blocker: Option<String>,
}

#[test]
fn law_reference_coverage_audits_template_references_against_local_corpus() {
    let registry = load_registry().expect("embedded template registry loads");
    let corpus = LawCatalog::embedded();
    let report = build_law_reference_coverage_report(&registry, corpus);

    assert!(!report.is_empty(), "expected template law references");

    let missing_diplomas = report
        .iter()
        .filter(|row| row.blocker.as_deref() == Some("missing local corpus diploma"))
        .collect::<Vec<_>>();
    assert!(
        missing_diplomas.is_empty(),
        "template law source_id without local corpus diploma:\n{}",
        format_report(&missing_diplomas)
    );

    let unresolved_without_blocker = report
        .iter()
        .filter(|row| !row.resolved && row.blocker.is_none())
        .collect::<Vec<_>>();
    assert!(
        unresolved_without_blocker.is_empty(),
        "unresolved references must carry an explicit blocker:\n{}",
        format_report(&unresolved_without_blocker)
    );

    let article_without_status = report
        .iter()
        .filter(|row| row.article.is_some() && row.corpus_status.is_none())
        .collect::<Vec<_>>();
    assert!(
        article_without_status.is_empty(),
        "single-article references must resolve to corpus articles or report a blocker:\n{}",
        format_report(&article_without_status)
    );

    assert!(
        report
            .iter()
            .filter(|row| row.corpus_status == Some("Pending"))
            .all(|row| !row.resolved && row.blocker.is_some()),
        "pending corpus/template references must not be treated as resolved authority:\n{}",
        format_report(
            &report
                .iter()
                .filter(|row| row.corpus_status == Some("Pending") && row.resolved)
                .collect::<Vec<_>>()
        )
    );

    let threshold_rows = report
        .iter()
        .filter(|row| row.threshold_id.is_some())
        .collect::<Vec<_>>();
    assert!(
        !threshold_rows.is_empty(),
        "expected template references derived from legal thresholds"
    );
    assert!(
        threshold_rows
            .iter()
            .all(|row| !row.resolved
                && row.blocker.as_deref() == Some("legal threshold value pending")),
        "threshold-backed template references must stay unresolved/pending:\n{}",
        format_report(&threshold_rows)
    );

    for threshold in LEGAL_THRESHOLDS {
        assert!(
            threshold.value.is_none(),
            "legal threshold {} must remain value: None",
            threshold.id
        );
        let rendered = threshold.render();
        assert!(
            rendered.starts_with("[a definir: ") && rendered.ends_with(']'),
            "unresolved threshold {} should render the pending marker, got {rendered:?}",
            threshold.id
        );
        let without_article_ref = rendered.replacen(threshold.article_ref, "", 1);
        assert!(
            !without_article_ref.chars().any(|c| c.is_ascii_digit()),
            "threshold {} emitted a digit outside the citation: {rendered:?}",
            threshold.id
        );
    }
}

fn build_law_reference_coverage_report(
    registry: &chancela_templates::Registry,
    corpus: &LawCatalog,
) -> Vec<LawReferenceAuditRow> {
    let mut rows = Vec::new();

    for spec in registry.specs() {
        for reference in &spec.law_references {
            assert_eq!(
                reference.verification,
                TemplateLawReferenceVerification::Pending,
                "{} {}: template law references must not claim legal verification",
                spec.id,
                reference.citation
            );

            let diploma = corpus.diploma(&reference.source_id);
            let threshold = reference.threshold_id.as_deref().map(|id| {
                find_threshold(id).unwrap_or_else(|| panic!("unknown threshold id {id}"))
            });
            let article = reference
                .article
                .as_deref()
                .and_then(|article| corpus.article(&reference.source_id, article));
            let corpus_status = match (diploma, article, reference.article.as_deref()) {
                (None, _, _) => None,
                (Some(_), Some(article), Some(_)) => Some(status_label(article.verification)),
                (Some(_), None, Some(_)) => None,
                (Some(diploma), _, None) => diploma_status(diploma),
            };
            let blocker = if diploma.is_none() {
                Some("missing local corpus diploma".to_string())
            } else if reference.article.is_some() && article.is_none() {
                Some("missing local corpus article".to_string())
            } else if threshold.is_some_and(|threshold| threshold.value.is_none()) {
                Some("legal threshold value pending".to_string())
            } else if corpus_status == Some("Pending") {
                Some("corpus text pending local authentic source".to_string())
            } else {
                None
            };

            if let Some(article) = article {
                match article.verification {
                    Verification::Verified => {
                        assert!(
                            article.source.is_complete(),
                            "{} {}: verified article must keep complete provenance",
                            spec.id,
                            article.label
                        );
                        assert!(
                            !article.body.trim().is_empty(),
                            "{} {}: verified article must carry local corpus text",
                            spec.id,
                            article.label
                        );
                    }
                    Verification::AutomatedReview => {
                        // Automated-review text is held to the same authenticity gate as Verified
                        // (complete source + real body) but is explicitly NOT human-approved.
                        assert!(
                            article.source.is_complete(),
                            "{} {}: automated-review article must keep complete provenance",
                            spec.id,
                            article.label
                        );
                        assert!(
                            !article.body.trim().is_empty(),
                            "{} {}: automated-review article must carry local corpus text",
                            spec.id,
                            article.label
                        );
                        assert!(
                            !article.is_verified(),
                            "{} {}: automated-review article must not read as human-Verified",
                            spec.id,
                            article.label
                        );
                    }
                    Verification::Pending => {
                        assert!(
                            !article.source.is_complete(),
                            "{} {}: pending article must not carry complete-source authority",
                            spec.id,
                            article.label
                        );
                        assert_eq!(
                            article.display_body(),
                            UNVERIFIED_MARKER,
                            "{} {}: pending article must render only the unverified marker",
                            spec.id,
                            article.label
                        );
                    }
                }
            }

            rows.push(LawReferenceAuditRow {
                template_id: spec.id.clone(),
                source_id: reference.source_id.clone(),
                article: reference.article.clone(),
                reference_source: reference_source_label(reference.source),
                threshold_id: reference.threshold_id.clone(),
                corpus_status,
                resolved: blocker.is_none(),
                blocker,
            });
        }
    }

    rows.sort_by(|a, b| {
        (
            a.template_id.as_str(),
            a.source_id.as_str(),
            a.article.as_deref().unwrap_or(""),
            a.reference_source,
            a.threshold_id.as_deref().unwrap_or(""),
        )
            .cmp(&(
                b.template_id.as_str(),
                b.source_id.as_str(),
                b.article.as_deref().unwrap_or(""),
                b.reference_source,
                b.threshold_id.as_deref().unwrap_or(""),
            ))
    });
    rows
}

fn diploma_status(diploma: &LawDiploma) -> Option<&'static str> {
    if diploma
        .articles
        .iter()
        .any(|article| matches!(article.verification, Verification::Pending))
    {
        Some("Pending")
    } else if diploma
        .articles
        .iter()
        .any(|article| matches!(article.verification, Verification::Verified))
    {
        Some("Verified")
    } else {
        None
    }
}

fn status_label(status: Verification) -> &'static str {
    match status {
        Verification::Verified => "Verified",
        Verification::AutomatedReview => "AutomatedReview",
        Verification::Pending => "Pending",
    }
}

fn reference_source_label(source: TemplateLawReferenceSource) -> &'static str {
    match source {
        TemplateLawReferenceSource::RulePack => "RulePack",
        TemplateLawReferenceSource::ThresholdRegistry => "ThresholdRegistry",
    }
}

fn format_report(rows: &[&LawReferenceAuditRow]) -> String {
    rows.iter()
        .map(|row| {
            format!(
                "template_id={} source_id={} article={} reference_source={} threshold_id={} \
                 corpus_status={} resolved={} blocker={}",
                row.template_id,
                row.source_id,
                row.article.as_deref().unwrap_or("-"),
                row.reference_source,
                row.threshold_id.as_deref().unwrap_or("-"),
                row.corpus_status.unwrap_or("-"),
                row.resolved,
                row.blocker.as_deref().unwrap_or("-")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
