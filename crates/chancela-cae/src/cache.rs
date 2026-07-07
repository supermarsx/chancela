//! Cache + staleness + auto-update entry points (§2.3 + §2.5): load order (valid cache → embedded),
//! atomic cache write, manual [`refresh`], and the non-blocking startup [`spawn_background_refresh`].

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::catalog::{CaeCatalog, CaeMetadata, CaeOrigin};
use crate::dataset::CaeDataset;
use crate::error::CaeError;
use crate::source::{CaeSource, HttpCaeSource};

/// Default staleness window for the background refresh. CAE tables change rarely (a revision every
/// ~15 years), so a long TTL keeps the offline path quiet.
pub const DEFAULT_CAE_TTL: Duration = Duration::days(30);

/// The cache file name inside `CHANCELA_DATA_DIR`.
pub const CACHE_FILE: &str = "cae-catalog.json";

/// A parsed catalog + when it was fetched; reports staleness on a TTL (mirrors `CachedTsl`).
#[derive(Clone, Debug)]
pub struct CachedCae {
    catalog: CaeCatalog,
    fetched_at: OffsetDateTime,
}

impl CachedCae {
    /// Wrap a catalog fetched at `fetched_at`.
    pub fn new(catalog: CaeCatalog, fetched_at: OffsetDateTime) -> Self {
        Self {
            catalog,
            fetched_at,
        }
    }

    /// The cached catalog.
    pub fn catalog(&self) -> &CaeCatalog {
        &self.catalog
    }

    /// When it was fetched.
    pub fn fetched_at(&self) -> OffsetDateTime {
        self.fetched_at
    }

    /// Whether the cache should be refreshed as of `now` (its TTL window has elapsed).
    pub fn is_stale(&self, now: OffsetDateTime, ttl: Duration) -> bool {
        now >= self.fetched_at + ttl
    }
}

/// Result of a [`refresh`] attempt, for the API/ledger.
#[derive(Clone, Debug)]
pub struct CaeRefreshOutcome {
    pub updated: bool,
    pub metadata: CaeMetadata,
    pub note: String,
}

/// Load order for a data-dir-backed binary: a VALID `cae-catalog.json` (parse + structural
/// integrity) that is NEWER than the embedded dataset → else the embedded catalog. Never errors:
/// a missing/corrupt/older cache logs (once) and falls back to the embedded copy.
pub fn load_catalog(data_dir: Option<&Path>) -> CaeCatalog {
    let embedded = CaeCatalog::embedded();
    let Some(dir) = data_dir else {
        return embedded.clone();
    };
    let path = dir.join(CACHE_FILE);
    match read_cache_file(&path) {
        Ok(Some(cache)) if supersedes(cache.metadata(), embedded.metadata()) => cache,
        Ok(_) => embedded.clone(),
        Err(e) => {
            eprintln!(
                "chancela-cae: ignoring invalid cache {} ({e}); using embedded catalog",
                path.display()
            );
            embedded.clone()
        }
    }
}

/// Read + validate the cache file. `Ok(None)` when the file is absent; `Err` when present but
/// unreadable/malformed/failing integrity.
fn read_cache_file(path: &Path) -> Result<Option<CaeCatalog>, CaeError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(CaeError::Http(format!("read {}: {e}", path.display()))),
    };
    let ds = CaeDataset::from_slice(&bytes)?;
    let catalog = CaeCatalog::from_dataset_with_origin(ds, CaeOrigin::Cache)?;
    Ok(Some(catalog))
}

/// Atomically persist a dataset as the cache (temp file + rename; mirrors the settings write). The
/// parent directory is created if missing.
pub fn write_cache_atomic(data_dir: &Path, ds: &CaeDataset) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let path = data_dir.join(CACHE_FILE);
    let json = serde_json::to_vec_pretty(ds).map_err(std::io::Error::other)?;
    let tmp = tmp_path(&path);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, &path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Fetch from `source`, validate, and — if it supersedes the currently active catalog — persist the
/// cache (when `data_dir` is set) and return the new catalog. A no-op-safe helper the API's refresh
/// endpoint calls; a same/older dataset returns the current catalog with `updated = false`.
pub fn refresh(
    source: &dyn CaeSource,
    data_dir: Option<&Path>,
) -> Result<(CaeCatalog, CaeRefreshOutcome), CaeError> {
    let ds = source.fetch()?;
    let fetched = CaeCatalog::from_dataset_with_origin(ds.clone(), CaeOrigin::Cache)?;
    let current = load_catalog(data_dir);

    if !supersedes(fetched.metadata(), current.metadata()) {
        let outcome = CaeRefreshOutcome {
            updated: false,
            metadata: current.metadata().clone(),
            note: "fetched dataset does not supersede the active catalog".to_owned(),
        };
        return Ok((current, outcome));
    }

    let note = match data_dir {
        Some(dir) => {
            write_cache_atomic(dir, &ds)
                .map_err(|e| CaeError::Config(format!("failed to write cache: {e}")))?;
            format!(
                "cache updated to dataset generated {}",
                fetched.metadata().generated_at
            )
        }
        None => "refreshed in memory (no data dir configured; not persisted)".to_owned(),
    };
    let outcome = CaeRefreshOutcome {
        updated: true,
        metadata: fetched.metadata().clone(),
        note,
    };
    Ok((fetched, outcome))
}

/// Spawn a detached `std::thread` that, IFF a source URL is configured AND the cache is stale AND
/// the fetch succeeds, writes the cache — otherwise silently does nothing. Never blocks, never
/// panics on offline/misconfig. The binary calls this once at startup; it returns immediately.
pub fn spawn_background_refresh(data_dir: Option<PathBuf>) {
    std::thread::spawn(move || {
        // No configured URL → nothing to do (the common, offline case).
        let source = match HttpCaeSource::from_env() {
            Ok(s) => s,
            Err(_) => return,
        };
        // Skip when the cache file is present and still within the TTL.
        if let Some(dir) = &data_dir {
            if cache_is_fresh(&dir.join(CACHE_FILE)) {
                return;
            }
        }
        match refresh(&source, data_dir.as_deref()) {
            Ok((_, outcome)) if outcome.updated => {
                eprintln!(
                    "chancela-cae: background refresh updated the cache ({})",
                    outcome.note
                );
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("chancela-cae: background refresh failed, keeping current data: {e}");
            }
        }
    });
}

/// Whether the cache file exists and was modified within [`DEFAULT_CAE_TTL`].
fn cache_is_fresh(path: &Path) -> bool {
    let ttl = std::time::Duration::from_secs(DEFAULT_CAE_TTL.whole_seconds().max(0) as u64);
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|elapsed| elapsed < ttl)
}

/// Whether `candidate` should replace `active`: different data (digest) and not older by
/// `generated_at`. If timestamps do not parse, a digest change alone decides.
pub(crate) fn supersedes(candidate: &CaeMetadata, active: &CaeMetadata) -> bool {
    if candidate.digest == active.digest {
        return false;
    }
    match (
        OffsetDateTime::parse(&candidate.generated_at, &Rfc3339),
        OffsetDateTime::parse(&active.generated_at, &Rfc3339),
    ) {
        (Ok(cand), Ok(act)) => cand >= act,
        _ => true,
    }
}

/// A unique sibling temp path for the atomic write (no `uuid` dep here — pid + a monotonic counter
/// keep concurrent writers from colliding on the temp file before their renames).
fn tmp_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| CACHE_FILE.into());
    name.push(format!(".{}.{seq}.tmp", std::process::id()));
    path.with_file_name(name)
}
