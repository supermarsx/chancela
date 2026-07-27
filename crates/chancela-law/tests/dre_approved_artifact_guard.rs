//! Operator dry-run guard tests for approved rendered DRE artifacts.
//!
//! These tests use a fake local artifact fixture. They do not add real DRE text, do not alter the
//! embedded corpus, and do not flip any manifest row to Verified/Approved in the committed manifest.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/source/dre_approved_artifact_guard.py"
);
const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/law_corpus.json");
const CURRENT_MANIFEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/source/dre-captures.manifest.json"
);
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/dre-approved-artifact/fake-csc-approved-render.html"
);

#[test]
fn current_pending_manifest_does_not_accept_a_local_artifact() {
    let output = run_guard([FIXTURE, "--manifest", CURRENT_MANIFEST, "--corpus", CORPUS]);
    assert!(
        !output.status.success(),
        "current Pending manifest must not approve any local artifact"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no manifest-approved artifact row matches"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn approved_fixture_reports_only_covered_pending_articles() {
    let tmp = TestDir::new("dre-approved-ok");
    let artifact = tmp.copy_fixture();
    let manifest = tmp.write_manifest(
        &artifact,
        &sha256(&artifact),
        "Approved",
        "Approved",
        true,
        &["255", "399"],
    );

    let output = run_guard([
        artifact.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--corpus",
        CORPUS,
        "--diploma-id",
        "csc",
    ]);
    assert!(
        output.status.success(),
        "guard should accept the approved fake fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["status"], "ok");
    assert_eq!(report["diploma_id"], "csc");
    assert_eq!(
        report["would_promote_articles"],
        Value::Array(vec![Value::from("255"), Value::from("399")])
    );
    assert!(
        report["pending_uncovered_articles"]
            .as_array()
            .unwrap()
            .contains(&Value::from("56")),
        "uncovered articles must stay out of would_promote"
    );
}

#[test]
fn sha256_mismatch_fails_closed() {
    let tmp = TestDir::new("dre-approved-bad-sha");
    let artifact = tmp.copy_fixture();
    let manifest = tmp.write_manifest(
        &artifact,
        &"0".repeat(64),
        "Approved",
        "Approved",
        true,
        &["255"],
    );

    let output = run_guard([
        artifact.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--corpus",
        CORPUS,
        "--diploma-id",
        "csc",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("sha256 mismatch"));
}

#[test]
fn missing_approval_marker_fails_closed() {
    let tmp = TestDir::new("dre-approved-missing-marker");
    let artifact = tmp.copy_fixture();
    let manifest = tmp.write_manifest(
        &artifact,
        &sha256(&artifact),
        "Approved",
        "Approved",
        false,
        &["255"],
    );

    let output = run_guard([
        artifact.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--corpus",
        CORPUS,
        "--diploma-id",
        "csc",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("approval_marker"));
}

#[test]
fn unknown_article_coverage_fails_closed() {
    let tmp = TestDir::new("dre-approved-unknown-coverage");
    let artifact = tmp.copy_fixture();
    let manifest = tmp.write_manifest(
        &artifact,
        &sha256(&artifact),
        "Approved",
        "Approved",
        true,
        &["255", "9999"],
    );

    let output = run_guard([
        artifact.to_str().unwrap(),
        "--manifest",
        manifest.to_str().unwrap(),
        "--corpus",
        CORPUS,
        "--diploma-id",
        "csc",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("absent from corpus"));
}

#[test]
fn test_dirs_with_the_same_label_and_timestamp_are_unique_and_cleaned_on_drop() {
    const DIR_COUNT: usize = 32;
    const FIXED_TIMESTAMP_NANOS: u128 = 1_753_545_600_000_000_000;

    let start = std::sync::Arc::new(std::sync::Barrier::new(DIR_COUNT));
    let handles = (0..DIR_COUNT)
        .map(|_| {
            let start = std::sync::Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                let dir = TestDir::new_at_timestamp("dre-approved-fixed", FIXED_TIMESTAMP_NANOS);
                let path = dir.path.clone();
                assert!(path.is_dir(), "DRE guard test directory should exist");
                (dir, path)
            })
        })
        .collect::<Vec<_>>();

    let dirs = handles
        .into_iter()
        .map(|handle| handle.join().expect("DRE guard test directory worker"))
        .collect::<Vec<_>>();
    let paths = dirs
        .iter()
        .map(|(_, path)| path.clone())
        .collect::<std::collections::HashSet<_>>();

    assert_eq!(paths.len(), DIR_COUNT);
    assert!(paths.iter().all(|path| path.is_dir()));

    drop(dirs);
    assert!(paths.iter().all(|path| !path.exists()));
}

fn run_guard<const N: usize>(args: [&str; N]) -> std::process::Output {
    let python = std::env::var("PYTHON")
        .or_else(|_| std::env::var("PYTHON3"))
        .unwrap_or_else(|_| "python".to_owned());
    Command::new(python)
        .arg(SCRIPT)
        .args(args)
        .output()
        .expect("run dre approved artifact guard")
}

struct TestDir {
    path: PathBuf,
}

static NEXT_TEST_DIR_ID: AtomicU64 = AtomicU64::new(0);

impl TestDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self::new_at_timestamp(label, unique)
    }

    fn new_at_timestamp(label: &str, timestamp_nanos: u128) -> Self {
        let path = std::env::temp_dir().join(format!(
            "{label}-{}-{timestamp_nanos}-{}",
            std::process::id(),
            NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn copy_fixture(&self) -> PathBuf {
        let artifact = self.path.join("fake-csc-approved-render.html");
        fs::copy(FIXTURE, &artifact).unwrap();
        artifact
    }

    fn write_manifest(
        &self,
        artifact: &Path,
        sha256: &str,
        reviewer_status: &str,
        legal_approval_status: &str,
        include_marker: bool,
        article_ids: &[&str],
    ) -> PathBuf {
        let manifest = self.path.join("dre-captures.manifest.json");
        let artifact_name = artifact.file_name().unwrap().to_string_lossy();
        let marker = if include_marker {
            r#""LEGAL_APPROVED_FOR_VERIFIED""#
        } else {
            "null"
        };
        let article_json = article_ids
            .iter()
            .map(|id| format!(r#""{id}""#))
            .collect::<Vec<_>>()
            .join(", ");
        let json = format!(
            r#"{{
  "schema_version": 1,
  "source_authority": "Diario da Republica Eletronico",
  "approval_marker_required": "LEGAL_APPROVED_FOR_VERIFIED",
  "captures": [
    {{
      "diploma_id": "csc",
      "official_page_url": "https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975",
      "eli": "https://data.dre.pt/eli/dec-lei/262/1986/p/cons/20260101",
      "captured_artifact_path": "{artifact_name}",
      "capture_timestamp": "2026-07-09T00:00:00Z",
      "sha256": "{sha256}",
      "article_ids": [{article_json}],
      "reviewer_status": "{reviewer_status}",
      "legal_approval_status": "{legal_approval_status}",
      "approval_marker": {marker}
    }}
  ]
}}
"#
        );
        fs::write(&manifest, json).unwrap();
        manifest
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn sha256(path: &Path) -> String {
    let bytes = fs::read(path).unwrap();
    format!("{:x}", Sha256::digest(bytes))
}
