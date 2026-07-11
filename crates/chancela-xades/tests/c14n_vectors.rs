//! Reference-vector suite for the in-crate XML canonicalizer (t67-e2, plan §0.2 / §5 risk 1).
//!
//! Each vector is a triple under `tests/fixtures/c14n/`:
//!   * `<name>.in.xml`   — the input document,
//!   * `<name>.out`      — the exact expected canonical bytes (no trailing newline),
//!   * `<name>.meta.json` — `{ algorithm, mode, id?, inclusive_prefixes? }`.
//!
//! The vectors are derived from the W3C Canonical XML 1.0 and Exclusive XML Canonicalization RECs
//! and the behaviours exercised by the Apache Santuario / xmlsec interop test data (namespace
//! pruning, PrefixList, default-namespace handling, attribute ordering, character escaping,
//! comment/PI handling, and line-ending / attribute-value normalization). These MUST pass before
//! any XAdES level machinery is trusted.

use std::path::{Path, PathBuf};

use chancela_xades::c14n::{C14nAlgorithm, canonicalize_document, canonicalize_element_by_id};
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/c14n")
}

fn parse_alg(s: &str) -> C14nAlgorithm {
    match s {
        "exclusive" => C14nAlgorithm::ExclusiveWithoutComments,
        "exclusive-with-comments" => C14nAlgorithm::ExclusiveWithComments,
        "inclusive" => C14nAlgorithm::InclusiveWithoutComments,
        "inclusive-with-comments" => C14nAlgorithm::InclusiveWithComments,
        other => panic!("unknown algorithm in fixture meta: {other}"),
    }
}

fn run_vector(meta_path: &Path) {
    let name = meta_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .trim_end_matches(".meta.json")
        .to_string();
    let dir = meta_path.parent().unwrap();
    let input = std::fs::read(dir.join(format!("{name}.in.xml")))
        .unwrap_or_else(|e| panic!("read {name}.in.xml: {e}"));
    let expected = std::fs::read(dir.join(format!("{name}.out")))
        .unwrap_or_else(|e| panic!("read {name}.out: {e}"));
    let meta: Value = serde_json::from_slice(
        &std::fs::read(meta_path).unwrap_or_else(|e| panic!("read {name}.meta.json: {e}")),
    )
    .unwrap_or_else(|e| panic!("parse {name}.meta.json: {e}"));

    let alg = parse_alg(meta["algorithm"].as_str().expect("algorithm"));
    let incl_owned: Vec<String> = meta
        .get("inclusive_prefixes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().expect("prefix string").to_string())
                .collect()
        })
        .unwrap_or_default();
    let incl: Vec<&str> = incl_owned.iter().map(String::as_str).collect();

    let got = match meta["mode"].as_str().expect("mode") {
        "document" => canonicalize_document(&input, alg, &incl).expect("canonicalize document"),
        "id" => {
            let id = meta["id"].as_str().expect("id for mode=id");
            canonicalize_element_by_id(&input, id, alg, &incl).expect("canonicalize by id")
        }
        other => panic!("unknown mode: {other}"),
    };

    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&expected),
        "\nvector `{name}` mismatch\n--- expected ---\n{}\n--- got ---\n{}\n",
        String::from_utf8_lossy(&expected),
        String::from_utf8_lossy(&got),
    );
    assert_eq!(got, expected, "vector `{name}`: byte-exact mismatch");
}

#[test]
fn all_c14n_reference_vectors_pass() {
    let dir = fixtures_dir();
    let mut metas: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read fixtures dir {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.to_str()
                .map(|s| s.ends_with(".meta.json"))
                .unwrap_or(false)
        })
        .collect();
    metas.sort();
    assert!(
        metas.len() >= 12,
        "expected the committed reference-vector suite (>=12 vectors), found {}",
        metas.len()
    );
    for meta in metas {
        run_vector(&meta);
    }
}
