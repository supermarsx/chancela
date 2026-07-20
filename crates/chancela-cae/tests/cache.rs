//! Cache load-order, staleness, atomic write, and refresh/integrity behaviour — all offline.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use chancela_cae::{
    BytesCaeSource, CachedCae, CaeCatalog, CaeDataset, CaeError, CaeOrigin, CaeRevision,
    DEFAULT_CAE_TTL, FileCaeSource, load_catalog, refresh, write_cache_atomic,
};
use time::macros::datetime;

/// A unique temp dir removed on drop (no `tempfile` dependency in this crate).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("chancela-cae-test-{}-{seq}", std::process::id()));
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

const UPDATE_FIXTURE: &str = include_str!("../fixtures/cae_update.json");
const CORRUPT_FIXTURE: &str = include_str!("../fixtures/cae_corrupt.json");

fn update_dataset() -> CaeDataset {
    serde_json::from_str(UPDATE_FIXTURE).expect("update fixture parses")
}

#[test]
fn cached_cae_is_stale_around_ttl() {
    let cache = CachedCae::new(
        CaeCatalog::embedded().clone(),
        datetime!(2026-01-01 0:00 UTC),
    );
    assert!(!cache.is_stale(datetime!(2026-01-15 0:00 UTC), DEFAULT_CAE_TTL));
    assert!(cache.is_stale(datetime!(2026-02-15 0:00 UTC), DEFAULT_CAE_TTL));
    // Exactly at the boundary counts as stale.
    assert!(cache.is_stale(datetime!(2026-01-31 0:00 UTC), DEFAULT_CAE_TTL));
}

#[test]
fn load_catalog_without_dir_is_embedded() {
    let cat = load_catalog(None);
    assert_eq!(cat.metadata().origin, CaeOrigin::Embedded);
    assert_eq!(cat.metadata().counts.rev4.total(), 1962);
}

#[test]
fn load_catalog_with_empty_dir_is_embedded() {
    let dir = TempDir::new();
    let cat = load_catalog(Some(dir.path()));
    assert_eq!(cat.metadata().origin, CaeOrigin::Embedded);
}

#[test]
fn load_catalog_prefers_a_valid_newer_cache() {
    let dir = TempDir::new();
    write_cache_atomic(dir.path(), &update_dataset()).unwrap();

    let cat = load_catalog(Some(dir.path()));
    assert_eq!(cat.metadata().origin, CaeOrigin::Cache);
    // The (small) update supersedes the embedded catalog.
    assert_eq!(cat.metadata().counts.rev4.total(), 5);
    assert_eq!(
        cat.lookup("01111", Some(CaeRevision::Rev4))
            .unwrap()
            .designation,
        "Subclasse de teste"
    );
}

#[test]
fn load_catalog_ignores_an_older_cache() {
    let dir = TempDir::new();
    let older = CaeDataset {
        generated_at: "2020-01-01T00:00:00Z".to_owned(),
        ..update_dataset()
    };
    write_cache_atomic(dir.path(), &older).unwrap();

    // Older than the embedded build date → embedded wins.
    let cat = load_catalog(Some(dir.path()));
    assert_eq!(cat.metadata().origin, CaeOrigin::Embedded);
    assert_eq!(cat.metadata().counts.rev4.total(), 1962);
}

#[test]
fn load_catalog_falls_back_on_corrupt_cache() {
    let dir = TempDir::new();
    std::fs::write(dir.path().join("cae-catalog.json"), CORRUPT_FIXTURE).unwrap();
    // Bad cache logs + falls back; never errors.
    let cat = load_catalog(Some(dir.path()));
    assert_eq!(cat.metadata().origin, CaeOrigin::Embedded);
}

#[test]
fn write_cache_atomic_round_trips() {
    let dir = TempDir::new();
    let ds = update_dataset();
    write_cache_atomic(dir.path(), &ds).unwrap();
    let bytes = std::fs::read(dir.path().join("cae-catalog.json")).unwrap();
    let back: CaeDataset = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.rev4.len(), ds.rev4.len());
    assert_eq!(back.generated_at, ds.generated_at);
}

#[test]
fn refresh_over_bytes_source_writes_and_prefers_cache() {
    let dir = TempDir::new();
    let source = BytesCaeSource::new(UPDATE_FIXTURE.as_bytes().to_vec());

    let (catalog, outcome) = refresh(&source, Some(dir.path())).unwrap();
    assert!(outcome.updated);
    assert_eq!(catalog.metadata().origin, CaeOrigin::Cache);
    assert!(dir.path().join("cae-catalog.json").exists());
    assert_eq!(outcome.metadata.counts.rev4.total(), 5);

    // A subsequent load now sees the cache.
    assert_eq!(
        load_catalog(Some(dir.path())).metadata().origin,
        CaeOrigin::Cache
    );

    // Refreshing the same data again is a no-op update.
    let (_, again) = refresh(&source, Some(dir.path())).unwrap();
    assert!(!again.updated);
}

#[test]
fn refresh_rejects_a_corrupt_update_and_keeps_current() {
    let dir = TempDir::new();
    let source = BytesCaeSource::new(CORRUPT_FIXTURE.as_bytes().to_vec());
    let err = refresh(&source, Some(dir.path())).unwrap_err();
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
    // Nothing was written; the embedded catalog remains the active one.
    assert!(!dir.path().join("cae-catalog.json").exists());
    assert_eq!(
        load_catalog(Some(dir.path())).metadata().origin,
        CaeOrigin::Embedded
    );
}

#[test]
fn refresh_rejects_unparseable_bytes() {
    let dir = TempDir::new();
    let source = BytesCaeSource::new(b"{ this is not a dataset".to_vec());
    let err = refresh(&source, Some(dir.path())).unwrap_err();
    assert!(matches!(err, CaeError::Parse(_)), "got {err:?}");
}

#[test]
fn file_source_reads_a_fixture() {
    let dir = TempDir::new();
    let path = dir.path().join("update.json");
    std::fs::write(&path, UPDATE_FIXTURE).unwrap();
    let source = FileCaeSource::new(&path);
    let (catalog, outcome) = refresh(&source, Some(dir.path())).unwrap();
    assert!(outcome.updated);
    assert_eq!(catalog.metadata().counts.rev4.total(), 5);
}

#[test]
fn from_dataset_rejects_orphan_node() {
    let ds: CaeDataset = serde_json::from_str(CORRUPT_FIXTURE).unwrap();
    let err = CaeCatalog::from_dataset(ds).unwrap_err();
    assert!(matches!(err, CaeError::Integrity(_)), "got {err:?}");
}
