//! Official-source obtainer engine — all offline (plan t23 §3 honest boundary).
//!
//! The load-bearing test [`vendored_obtain_reproduces_official_table`] parses the committed real
//! Diário da República diploma PDFs through the in-app `lopdf` port and proves the result equals the
//! embedded dataset (generated offline by `data/source/gen_cae.py` via pymupdf): exact official
//! per-level counts AND byte-equal designations on a spread of spot-check codes. The remaining tests
//! exercise the `obtain_and_supersede` pipeline (supersede, no-op, reject-on-doubt keeps the
//! known-good catalog) via an injected `OfficialCaeSource` test double. The live remote fetch is
//! `network-tests`-gated in `tests/network.rs`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use chancela_cae::{
    CaeCatalog, CaeDataset, CaeError, CaeLevel, CaeRevision, DrPdfSource, EXPECTED_REV3_COUNTS,
    EXPECTED_REV4_COUNTS, ObtainedDataset, OfficialCaeSource, OfficialSourceKind,
    obtain_and_supersede, verify_fidelity, write_cache_atomic,
};

/// A unique temp dir removed on drop (no `tempfile` dependency in this crate; mirrors `cache.rs`).
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("chancela-cae-obtain-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn vendored(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data/source")
        .join(name)
}

/// Obtain the full dataset from the committed real PDFs (the in-app parser output).
fn obtain_vendored() -> CaeDataset {
    DrPdfSource::from_files(&vendored("rev4.pdf"), &vendored("rev3.pdf"))
        .obtain()
        .expect("obtain parses the vendored diploma PDFs")
        .dataset
}

/// Spot-check codes with clean designations (a spread across both revisions and every level).
const REV4_SPOTS: &[&str] = &[
    "A", "B", "V", "35", "351", "3511", "35110", "68", "681", "6811", "68110", "68200", "41000",
    "62100", "47300",
];
const REV3_SPOTS: &[&str] = &[
    "A", "L", "01", "011", "68", "6810", "68100", "41200", "62010", "56101", "01111", "843",
];

/// THE critical cross-check: the in-app `lopdf` obtainer reproduces the offline-generated embedded
/// dataset — exact official totals (1962/1847) AND byte-equal designations on the spot codes.
#[test]
fn vendored_obtain_reproduces_official_table() {
    let ds = obtain_vendored();

    // Structural integrity + full-count fidelity both pass on the parsed dataset.
    let obtained = CaeCatalog::from_dataset(ds.clone()).expect("parsed dataset passes integrity");
    verify_fidelity(&obtained.metadata().counts).expect("parsed dataset passes fidelity");
    assert_eq!(obtained.metadata().counts.rev4, EXPECTED_REV4_COUNTS);
    assert_eq!(obtained.metadata().counts.rev3, EXPECTED_REV3_COUNTS);

    // Provenance recorded.
    let prov = ds.provenance.as_ref().expect("obtain records provenance");
    assert_eq!(prov.source_kind, OfficialSourceKind::DiarioRepublica);
    assert_eq!(prov.artifact_digest.len(), 64, "sha256 hex");
    assert!(!prov.retrieved_at.is_empty(), "retrieved_at set");
    assert!(prov.parser_version.contains("chancela-cae"), "parser tag");

    // Byte-equal designations against the embedded (pymupdf-generated) dataset — proves the Rust
    // port reproduces the Python output, not merely the right counts.
    let embedded = CaeCatalog::embedded();
    let spots = [
        (CaeRevision::Rev4, REV4_SPOTS),
        (CaeRevision::Rev3, REV3_SPOTS),
    ];
    for (rev, codes) in spots {
        for &code in codes {
            let got = obtained
                .lookup(code, Some(rev))
                .unwrap_or_else(|| panic!("{rev:?} {code} obtained"));
            let exp = embedded
                .lookup(code, Some(rev))
                .unwrap_or_else(|| panic!("{rev:?} {code} embedded"));
            assert_eq!(
                got.designation, exp.designation,
                "{rev:?} {code} designation"
            );
            assert_eq!(got.level, exp.level, "{rev:?} {code} level");
            assert_eq!(got.parent, exp.parent, "{rev:?} {code} parent");
        }
    }
}

/// End-to-end offline pipeline over the real vendored source: obtain → integrity → fidelity →
/// supersede (into a data dir) succeeds and yields the full catalog with provenance.
#[test]
fn vendored_obtain_and_supersede_end_to_end() {
    let dir = TempDir::new();
    let src = DrPdfSource::from_files(&vendored("rev4.pdf"), &vendored("rev3.pdf"));
    let (catalog, outcome) =
        obtain_and_supersede(&src, Some(dir.path())).expect("pipeline succeeds offline");
    assert_eq!(catalog.metadata().counts.rev4, EXPECTED_REV4_COUNTS);
    assert_eq!(catalog.metadata().counts.rev3, EXPECTED_REV3_COUNTS);
    verify_fidelity(&catalog.metadata().counts).expect("superseded catalog is full");
    assert!(
        outcome.updated,
        "obtained official data supersedes the embedded catalog"
    );
    assert!(
        dir.path().join("cae-catalog.json").exists(),
        "cache persisted"
    );
    assert!(
        catalog.metadata().provenance.is_some(),
        "provenance surfaced"
    );
}

/// An injected official source returning a canned dataset (the test-double DI seam).
struct CannedSource {
    dataset: CaeDataset,
    kind: OfficialSourceKind,
}
impl OfficialCaeSource for CannedSource {
    fn kind(&self) -> OfficialSourceKind {
        self.kind
    }
    fn obtain(&self) -> Result<ObtainedDataset, CaeError> {
        Ok(ObtainedDataset {
            dataset: self.dataset.clone(),
        })
    }
}

/// Base dataset (full, valid) restamped to a future date so it definitively supersedes the embedded.
fn future_full_dataset(marker_code: &str, marker: &str) -> CaeDataset {
    let mut ds = obtain_vendored();
    ds.generated_at = "2030-01-01T00:00:00Z".to_owned();
    for e in ds.rev4.iter_mut() {
        if e.code == marker_code {
            e.designation = marker.to_owned();
        }
    }
    ds
}

#[test]
fn supersede_writes_cache_and_swaps_catalog() {
    let dir = TempDir::new();
    let ds = future_full_dataset("A", "MARKER — obtido oficialmente.");
    let src = CannedSource {
        dataset: ds,
        kind: OfficialSourceKind::DiarioRepublica,
    };

    let (catalog, outcome) = obtain_and_supersede(&src, Some(dir.path())).expect("supersede");
    assert!(outcome.updated, "newer full dataset supersedes");
    assert!(
        dir.path().join("cae-catalog.json").exists(),
        "cache written"
    );
    assert_eq!(
        catalog
            .lookup("A", Some(CaeRevision::Rev4))
            .unwrap()
            .designation,
        "MARKER — obtido oficialmente.",
        "swapped-in data is served"
    );
    verify_fidelity(&catalog.metadata().counts).expect("still full");
}

#[test]
fn same_data_is_a_noop() {
    let dir = TempDir::new();
    let ds = future_full_dataset("A", "MARKER.");
    // Seed the cache with exactly this dataset, then obtain the same content again.
    write_cache_atomic(dir.path(), &ds).expect("seed cache");
    let src = CannedSource {
        dataset: ds,
        kind: OfficialSourceKind::DiarioRepublica,
    };
    let (_catalog, outcome) = obtain_and_supersede(&src, Some(dir.path())).expect("noop obtain");
    assert!(!outcome.updated, "identical data does not supersede");
}

#[test]
fn short_parse_is_rejected_and_keeps_known_good_catalog() {
    let dir = TempDir::new();
    // Seed a known-good full catalog.
    let good = future_full_dataset("A", "GOOD.");
    write_cache_atomic(dir.path(), &good).expect("seed good cache");
    let good_digest = CaeCatalog::from_dataset(good)
        .unwrap()
        .metadata()
        .digest
        .clone();

    // A structurally-valid but SHORT dataset (five leaf subclasses dropped) fails the fidelity gate.
    let mut short = future_full_dataset("A", "SHORT.");
    let mut dropped = 0;
    short.rev4.retain(|e| {
        if dropped < 5 && e.level == CaeLevel::Subclasse {
            dropped += 1;
            false
        } else {
            true
        }
    });
    // It still passes structural integrity (leaves have no children) — so only fidelity can catch it.
    CaeCatalog::from_dataset(short.clone()).expect("short dataset is structurally valid");

    let src = CannedSource {
        dataset: short,
        kind: OfficialSourceKind::DiarioRepublica,
    };
    let err = obtain_and_supersede(&src, Some(dir.path())).expect_err("short parse rejected");
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");

    // The known-good catalog is retained unchanged.
    let after = chancela_cae::load_catalog(Some(dir.path()));
    assert_eq!(after.metadata().digest, good_digest, "catalog untouched");
    verify_fidelity(&after.metadata().counts).expect("retained catalog still full");
}

#[test]
fn structurally_invalid_parse_is_rejected() {
    let dir = TempDir::new();
    // Drop a classe whose subclasse remains → an orphaned parent reference (integrity failure).
    let mut broken = future_full_dataset("A", "BROKEN.");
    broken.rev4.retain(|e| e.code != "6811");
    let src = CannedSource {
        dataset: broken,
        kind: OfficialSourceKind::DiarioRepublica,
    };
    let err = obtain_and_supersede(&src, Some(dir.path())).expect_err("integrity failure rejected");
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    assert!(
        !dir.path().join("cae-catalog.json").exists(),
        "nothing persisted on rejection"
    );
}
