//! DRE source-capture workflow guard.
//!
//! The DRE consolidated pages are JS-rendered, so Portuguese-law articles stay `Pending` until an
//! operator captures an official rendered artifact and legal review approves it. This test keeps
//! the capture manifest shape pinned and cross-checks any future DRE `Verified` article against it.

use std::collections::{HashMap, HashSet};

use chancela_law::LawCatalog;
use serde::Deserialize;

const MANIFEST: &str = include_str!("../data/source/dre-captures.manifest.json");
const REQUIRED_APPROVAL_MARKER: &str = "LEGAL_APPROVED_FOR_VERIFIED";
const DRE_DIPLOMA_IDS: &[&str] = &[
    "csc",
    "cc",
    "dl-268-94",
    "dl-76-a-2006",
    "cod-cooperativo",
    "lei-24-2012",
];

#[derive(Debug, Deserialize)]
struct DreCaptureManifest {
    schema_version: u32,
    source_authority: String,
    approval_marker_required: String,
    captures: Vec<DreCapture>,
}

#[derive(Debug, Deserialize)]
struct DreCapture {
    diploma_id: String,
    official_page_url: String,
    eli: String,
    captured_artifact_path: Option<String>,
    capture_timestamp: Option<String>,
    sha256: Option<String>,
    article_ids: Vec<String>,
    reviewer_status: String,
    legal_approval_status: String,
    approval_marker: Option<String>,
}

#[test]
fn dre_capture_manifest_has_required_operator_fields() {
    let manifest = parse_manifest();
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.source_authority, "Diario da Republica Eletronico");
    assert_eq!(manifest.approval_marker_required, REQUIRED_APPROVAL_MARKER);
    assert!(
        !manifest.captures.is_empty(),
        "DRE capture workflow must have at least one scoped row"
    );

    let mut seen = HashSet::new();
    for capture in &manifest.captures {
        assert!(!capture.diploma_id.trim().is_empty());
        assert!(
            capture
                .official_page_url
                .starts_with("https://diariodarepublica.pt/"),
            "{} official_page_url must be the official DRE rendered page",
            capture.diploma_id
        );
        assert!(
            capture.eli.starts_with("https://data.dre.pt/eli/"),
            "{} must carry the DRE ELI",
            capture.diploma_id
        );
        assert!(
            !capture.article_ids.is_empty(),
            "{} must list the article ids covered by the capture",
            capture.diploma_id
        );
        assert!(
            matches!(
                capture.reviewer_status.as_str(),
                "Pending" | "Approved" | "Rejected"
            ),
            "{} reviewer_status must be explicit",
            capture.diploma_id
        );
        assert!(
            matches!(
                capture.legal_approval_status.as_str(),
                "Pending" | "Approved" | "Rejected"
            ),
            "{} legal_approval_status must be explicit",
            capture.diploma_id
        );
        if capture.reviewer_status == "Pending" || capture.legal_approval_status == "Pending" {
            assert!(
                capture.captured_artifact_path.is_none()
                    && capture.capture_timestamp.is_none()
                    && capture.sha256.is_none()
                    && capture.approval_marker.is_none(),
                "{} Pending capture rows must not claim artifacts, digests, or approval markers",
                capture.diploma_id
            );
        }
        for article_id in &capture.article_ids {
            assert!(
                seen.insert((capture.diploma_id.as_str(), article_id.as_str())),
                "duplicate capture coverage for {}:{}",
                capture.diploma_id,
                article_id
            );
        }
    }
}

#[test]
fn all_pending_dre_articles_have_pending_capture_manifest_coverage() {
    let manifest = parse_manifest();
    let capture_index = capture_index(&manifest);
    let cat = LawCatalog::embedded();

    for &diploma_id in DRE_DIPLOMA_IDS {
        let diploma = cat
            .diploma(diploma_id)
            .unwrap_or_else(|| panic!("{diploma_id} must exist in embedded corpus"));
        for article in &diploma.articles {
            if article.is_verified() {
                continue;
            }
            let capture = capture_index
                .get(&(diploma_id, article.number.as_str()))
                .unwrap_or_else(|| {
                    panic!(
                        "Pending DRE article {diploma_id}:{} must be listed in dre-captures.manifest.json",
                        article.number
                    )
                });
            assert_eq!(capture.official_page_url, diploma.official_url);
            assert_eq!(Some(capture.eli.as_str()), diploma.eli.as_deref());
            assert_eq!(capture.reviewer_status, "Pending");
            assert_eq!(capture.legal_approval_status, "Pending");
            assert!(capture.captured_artifact_path.is_none());
            assert!(capture.capture_timestamp.is_none());
            assert!(capture.sha256.is_none());
            assert!(capture.approval_marker.is_none());
        }
    }
}

#[test]
fn csc_priority_capture_articles_still_exist_but_remain_pending() {
    let manifest = parse_manifest();
    let capture_index = capture_index(&manifest);

    let cat = LawCatalog::embedded();
    for article_id in ["255", "399"] {
        let capture = capture_index
            .get(&("csc", article_id))
            .unwrap_or_else(|| panic!("CSC {article_id} DRE capture coverage"));
        assert_eq!(
            capture.official_page_url,
            "https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975"
        );
        assert_eq!(
            capture.eli,
            "https://data.dre.pt/eli/dec-lei/262/1986/p/cons/20260101"
        );
        assert_eq!(capture.reviewer_status, "Pending");
        assert_eq!(capture.legal_approval_status, "Pending");
        assert!(capture.captured_artifact_path.is_none());
        assert!(capture.capture_timestamp.is_none());
        assert!(capture.sha256.is_none());
        assert!(capture.approval_marker.is_none());

        assert!(!cat.article("csc", article_id).unwrap().is_verified());
    }
}

#[test]
fn any_dre_verified_article_requires_an_approved_capture_artifact() {
    let manifest = parse_manifest();
    let approval = approved_capture_index(&manifest);
    let cat = LawCatalog::embedded();

    for diploma_id in [
        "csc",
        "cc",
        "dl-268-94",
        "dl-76-a-2006",
        "cod-cooperativo",
        "lei-24-2012",
    ] {
        for article in cat.articles_for(diploma_id) {
            if !article.is_verified() {
                continue;
            }
            assert!(
                approval.contains_key(&(diploma_id, article.number.as_str())),
                "DRE article {diploma_id}:{} is Verified without an approved captured artifact",
                article.number
            );
        }
    }
}

fn parse_manifest() -> DreCaptureManifest {
    serde_json::from_str(MANIFEST).expect("DRE capture manifest parses")
}

fn capture_index<'a>(
    manifest: &'a DreCaptureManifest,
) -> HashMap<(&'a str, &'a str), &'a DreCapture> {
    let mut index = HashMap::new();
    for capture in &manifest.captures {
        for article_id in &capture.article_ids {
            index.insert((capture.diploma_id.as_str(), article_id.as_str()), capture);
        }
    }
    index
}

fn approved_capture_index<'a>(
    manifest: &'a DreCaptureManifest,
) -> HashMap<(&'a str, &'a str), &'a DreCapture> {
    let mut approved = HashMap::new();
    for capture in &manifest.captures {
        let complete_artifact = capture
            .captured_artifact_path
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty() && !p.contains(".."))
            && capture
                .capture_timestamp
                .as_deref()
                .is_some_and(|ts| ts.ends_with('Z') || ts.ends_with("+00:00"))
            && capture.sha256.as_deref().is_some_and(|s| {
                s.len() == 64
                    && s.chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            });

        if capture.reviewer_status == "Approved"
            && capture.legal_approval_status == "Approved"
            && capture.approval_marker.as_deref() == Some(REQUIRED_APPROVAL_MARKER)
            && complete_artifact
        {
            for article_id in &capture.article_ids {
                approved.insert((capture.diploma_id.as_str(), article_id.as_str()), capture);
            }
        }
    }
    approved
}
