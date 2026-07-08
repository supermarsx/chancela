//! Ordered source chain (plan t23 §2.7): first-supersede-wins, per-entry failure recording, and the
//! all-fail-keeps-the-known-good-catalog guarantee — all offline over in-memory (`Bytes`) mirrors.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use chancela_cae::{
    CaeCatalog, CaeDataset, CaeEntry, CaeRevision, CaeSourceChain, CaeSourceFormat, ChainEntry,
    DrPdfSource, MirrorArtifactSource, OfficialCaeSource, OfficialSourceKind, load_catalog,
    obtain_from_chain, write_cache_atomic,
};

/// A unique temp dir removed on drop (mirrors `tests/obtain.rs`; no `tempfile` dep in this crate).
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("chancela-cae-chain-{}-{seq}", std::process::id()));
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

/// The full official dataset from the committed DR PDFs, with Rev.4 secção "A" restamped to `marker`
/// so a test can tell which source's data landed.
fn marked_dataset(marker: &str) -> CaeDataset {
    let mut ds = DrPdfSource::from_files(&vendored("rev4.pdf"), &vendored("rev3.pdf"))
        .obtain()
        .expect("obtain parses the vendored diploma PDFs")
        .dataset;
    for e in ds.rev4.iter_mut() {
        if e.code == "A" {
            e.designation = marker.to_owned();
        }
    }
    ds
}

/// Serialize a dataset as a flat Simple-JSON mirror array (level + parent present, i.e. verbatim).
fn simple_json_bytes(ds: &CaeDataset) -> Vec<u8> {
    let arr: Vec<&CaeEntry> = ds.rev4.iter().chain(ds.rev3.iter()).collect();
    serde_json::to_vec(&arr).expect("serialize simple-json array")
}

fn bytes_mirror(bytes: Vec<u8>) -> ChainEntry {
    ChainEntry::Mirror(MirrorArtifactSource::from_bytes(
        bytes,
        CaeSourceFormat::Auto,
    ))
}

/// The FIRST source that supersedes wins; later entries are not applied.
#[test]
fn first_superseding_source_wins() {
    let dir = TempDir::new();
    let chain = CaeSourceChain::new(vec![
        bytes_mirror(simple_json_bytes(&marked_dataset("PRIMEIRA FONTE."))),
        bytes_mirror(simple_json_bytes(&marked_dataset("SEGUNDA FONTE."))),
    ]);

    let out = obtain_from_chain(&chain, Some(dir.path()));
    assert!(out.refresh.updated, "a superseding source updates");
    assert!(out.winner.is_some(), "a winner is recorded");
    assert!(out.any_valid);
    assert!(out.failures.is_empty(), "no failures");
    assert_eq!(
        out.catalog
            .lookup("A", Some(CaeRevision::Rev4))
            .unwrap()
            .designation,
        "PRIMEIRA FONTE.",
        "the first source's data landed, not the second"
    );
    // A mirror obtain stamps Mirror provenance.
    assert_eq!(
        out.catalog
            .metadata()
            .provenance
            .as_ref()
            .unwrap()
            .source_kind,
        OfficialSourceKind::Mirror
    );
}

/// A failing entry is recorded and the chain falls through to the next entry that succeeds.
#[test]
fn failing_entry_is_recorded_and_chain_falls_through() {
    let dir = TempDir::new();
    let chain = CaeSourceChain::new(vec![
        bytes_mirror(b"garbage, not a CAE artifact".to_vec()),
        bytes_mirror(simple_json_bytes(&marked_dataset("A VÁLIDA."))),
    ]);

    let out = obtain_from_chain(&chain, Some(dir.path()));
    assert!(out.refresh.updated, "the valid fallback superseded");
    assert_eq!(
        out.catalog
            .lookup("A", Some(CaeRevision::Rev4))
            .unwrap()
            .designation,
        "A VÁLIDA."
    );
    assert_eq!(out.failures.len(), 1, "the garbage entry is recorded");
    assert!(
        !out.failures[0].error.is_empty(),
        "failure carries an error"
    );
}

/// When every source fails, the chain never touches the known-good catalog.
#[test]
fn all_sources_failing_keeps_known_good_catalog() {
    let dir = TempDir::new();

    // Seed a known-good, full, future-dated cache so it is the active catalog.
    let mut good = marked_dataset("CATÁLOGO BOM.");
    good.generated_at = "2030-01-01T00:00:00Z".to_owned();
    write_cache_atomic(dir.path(), &good).expect("seed good cache");
    let good_digest = CaeCatalog::from_dataset(good)
        .unwrap()
        .metadata()
        .digest
        .clone();

    let chain = CaeSourceChain::new(vec![
        bytes_mirror(b"not json".to_vec()),
        bytes_mirror(b"[{ still not valid".to_vec()),
    ]);

    let out = obtain_from_chain(&chain, Some(dir.path()));
    assert!(!out.refresh.updated, "nothing superseded");
    assert!(out.winner.is_none());
    assert!(!out.any_valid, "no source produced a valid dataset");
    assert_eq!(out.failures.len(), 2, "both failures recorded");

    // The known-good catalog is retained unchanged, on-disk and in the returned outcome.
    assert_eq!(
        out.catalog.metadata().digest,
        good_digest,
        "outcome catalog intact"
    );
    let after = load_catalog(Some(dir.path()));
    assert_eq!(after.metadata().digest, good_digest, "cache intact");
}

/// A source that fetches + parses but is not newer than the active catalog is valid (not a failure)
/// yet does not supersede.
#[test]
fn up_to_date_source_is_valid_but_not_a_winner() {
    let dir = TempDir::new();

    let mut ds = marked_dataset("MESMO CONTEÚDO.");
    ds.generated_at = "2030-01-01T00:00:00Z".to_owned();
    write_cache_atomic(dir.path(), &ds).expect("seed cache");
    // A mirror hosting the identical entries → identical content digest → does not supersede.
    let chain = CaeSourceChain::new(vec![bytes_mirror(simple_json_bytes(&ds))]);

    let out = obtain_from_chain(&chain, Some(dir.path()));
    assert!(!out.refresh.updated, "identical content does not supersede");
    assert!(out.winner.is_none());
    assert!(out.any_valid, "the source was valid, just not newer");
    assert!(out.failures.is_empty(), "up-to-date is not a failure");
}

/// The built-in official DR entry runs the digest-pinned two-diploma source (offline via file inputs
/// is exercised in `tests/obtain.rs`; here we confirm the entry type resolves and reports a label).
#[test]
fn official_chain_entry_has_a_label() {
    let entry = ChainEntry::official();
    assert!(entry.label().contains("Diário da República"));
    // Keep the built-in official source constructor exercised (no network in this test).
    let _ = DrPdfSource::official();
}

/// INE-first (the default preference, t37): the INE entry fails honestly and is recorded in
/// `failures`, and the next source fulfils the refresh — the "INE indisponível → fallback" behaviour,
/// with no silent substitution. (Uses a valid mirror in place of the DR pair so the test stays
/// offline; the api leg puts the real DR pair after INE.)
#[test]
fn ine_first_entry_fails_and_chain_falls_through_to_the_fallback() {
    let dir = TempDir::new();
    let chain = CaeSourceChain::new(vec![
        ChainEntry::ine(),
        bytes_mirror(simple_json_bytes(&marked_dataset("VIA FALLBACK."))),
    ]);

    let out = obtain_from_chain(&chain, Some(dir.path()));
    assert!(out.refresh.updated, "the fallback superseded");
    assert!(out.winner.is_some(), "a winner is recorded (the fallback)");
    assert_eq!(
        out.catalog
            .lookup("A", Some(CaeRevision::Rev4))
            .unwrap()
            .designation,
        "VIA FALLBACK."
    );
    // The INE failure is surfaced honestly, not swallowed.
    assert_eq!(out.failures.len(), 1, "the INE attempt is recorded");
    assert!(
        out.failures[0].entry.contains("INE"),
        "failure names the INE entry: {:?}",
        out.failures[0].entry
    );
    assert!(
        out.failures[0].error.contains("INE"),
        "failure carries the honest INE reason: {:?}",
        out.failures[0].error
    );
}
