//! Reference-vector suite for the in-crate XML canonicalizer (t67-e2, plan §0.2 / §5 risk 1;
//! interop-certified under wp26-xades E1).
//!
//! Each vector is a triple under `tests/fixtures/c14n/`:
//!   * `<name>.in.xml`   — the input document,
//!   * `<name>.out`      — the exact expected canonical bytes (no trailing newline),
//!   * `<name>.meta.json` — `{ algorithm, mode, id?, inclusive_prefixes?, rule, provenance }`.
//!
//! Every vector carries an auditable `provenance` string naming its external oracle. The oracle is
//! the standard itself: the W3C Canonical XML 1.0 REC (xml-c14n-20010315) and the Exclusive XML
//! Canonicalization 1.0 REC (xml-exc-c14n-20020718). Vectors fall into two honestly-labelled classes
//! (see `crates/chancela-xades/TESTING.md` for the full interop-certification write-up):
//!   * verbatim-REC worked examples transcribed byte-for-byte from a REC section (v18–v20), and
//!   * hand-derived-from-rule vectors whose expected bytes were computed by hand from a cited REC
//!     rule (v01–v17), each `provenance` string saying so explicitly.
//!
//! `xmlsec1` / EU DSS were not available offline, so no live third-party tool run backs these bytes;
//! the manual conformance procedure for a reference machine that has them is documented in
//! `TESTING.md`. These MUST pass before any XAdES level machinery is trusted.

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

    // Every committed vector must carry an auditable external-oracle citation (wp26-xades E1): a
    // non-empty `provenance` (which REC section / rule grounds the expected bytes) and a `rule`
    // one-liner. A vector with no provenance reads as self-generated and is rejected here.
    let provenance = meta["provenance"]
        .as_str()
        .unwrap_or_else(|| panic!("vector `{name}` is missing a `provenance` string"));
    assert!(
        provenance.trim().len() >= 20,
        "vector `{name}` has an empty/too-short `provenance`: {provenance:?}"
    );
    assert!(
        meta["rule"].as_str().map(str::trim).is_some_and(|r| !r.is_empty()),
        "vector `{name}` is missing a `rule` description"
    );

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
        metas.len() >= 20,
        "expected the committed reference-vector suite (>=20 vectors), found {}",
        metas.len()
    );
    for meta in metas {
        run_vector(&meta);
    }
}
