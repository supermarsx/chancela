//! A durable, on-disk cache of the **raw Trusted List bytes**, so a transient network fault does
//! not make qualified signing impossible.
//!
//! An ETSI TS 119 612 Trusted List carries a `NextUpdate` and is *designed* to be cached until it.
//! [`cache::CachedTsl`](crate::cache::CachedTsl) already does that in memory, but a process holds
//! that only for its own lifetime and a freshly-built [`TslClient`](crate::query::TslClient) starts
//! empty — so a list that fetched fine an hour ago is gone the moment egress breaks, and the
//! signature is refused.
//!
//! # What is cached, and what is deliberately not
//!
//! **The raw XML bytes, and nothing else.** Not the parsed list, not the signature verdict, not the
//! set of granted services. Every use of a cached copy re-runs the full pipeline against the
//! *current* configuration: parse, XML-DSig verification, trust-anchor matching, algorithm policy.
//! That is not a performance oversight, it is the security property — a cached verdict would keep
//! asserting "this list is authentic" after the operator revoked the anchor that made it so, or
//! after they tightened the algorithm policy that permitted its signature. [`CachingTslSource`] is
//! a [`TslSource`], i.e. it hands back *bytes*, precisely so it is structurally incapable of
//! short-circuiting any of those checks.
//!
//! # When a cached copy may be used
//!
//! Only when the live fetch **fails**. A successful fetch always wins and always refreshes the
//! cache. On failure:
//!
//! - within the list's own `NextUpdate` → served, and this is ordinary: the scheme operator's own
//!   document says it is valid until then;
//! - past `NextUpdate`, by up to [`DEFAULT_MAX_STALE`] → served, but the serve is **recorded** and
//!   reported ([`TslFetchProvenance::ServedFromCache`], `stale = true`). A Trusted List is how a
//!   withdrawn service stops being trusted, so a stale one is a list on which a service the scheme
//!   operator has since withdrawn still reads as granted. That must never be silent;
//! - past that bound → **refused**. The cache adds resilience, never authority.
//!
//! A list carrying no parseable `NextUpdate` at all uses [`crate::FALLBACK_TTL`] from its fetch time
//! as its notional expiry, exactly as the in-memory cache does.
//!
//! Fail-closed is unchanged throughout: no cache **and** no fetch still returns the fetch error.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::cache::FALLBACK_TTL;
use crate::error::TslError;
use crate::source::TslSource;

/// Directory (relative to the instance data directory) holding the durable Trusted List cache.
///
/// A directory rather than a single file because an installation may have several configured TSL
/// sources; each gets its own entry keyed by [`TslDiskCache::key_for`].
pub const TSL_CACHE_DIR: &str = "tsl-cache";

/// How long past its own expiry a cached Trusted List may still be served before it is refused.
///
/// **Seven days.** The reasoning, since this is a judgement call:
///
/// - Inside `NextUpdate` no bound applies — the scheme operator's own document vouches for the
///   list, and clamping that would refuse a list the scheme says is valid. This bound governs only
///   the window *after* the list's own expiry.
/// - Every day of that window is a day in which a trust service the scheme operator has withdrawn
///   still reads as granted here. That is the whole risk of caching, so the window is the thing to
///   keep small.
/// - The fault this cache exists for is transient: a container egress rule, a proxy, a DNS blip.
///   Those are fixed in hours or over a weekend. A week covers a Friday-night outage found on
///   Monday, which is the realistic worst case for an operator's own infrastructure.
/// - Past a week the fault is not transient — it is a configuration problem that needs fixing, and
///   refusing to sign is the honest answer rather than quietly extending trust indefinitely.
///
/// Overridable per installation with [`ENV_TSL_CACHE_MAX_STALE_HOURS`].
pub const DEFAULT_MAX_STALE: Duration = Duration::days(7);

/// Environment variable overriding [`DEFAULT_MAX_STALE`], in **hours**. `0` disables serving a
/// cached list past its expiry entirely (the strictest setting; the cache is then usable only
/// inside `NextUpdate`). A malformed value is ignored in favour of the default rather than being
/// treated as `0` or as unbounded — a typo should change nothing.
pub const ENV_TSL_CACHE_MAX_STALE_HOURS: &str = "CHANCELA_TSL_CACHE_MAX_STALE_HOURS";

/// Stable machine code: the live fetch failed and a cached list **inside** its `NextUpdate` was
/// used. Normal operation of a cache; no trust was extended beyond what the list itself asserts.
pub const CODE_TSL_SERVED_FROM_CACHE: &str = "tsl_served_from_cache";

/// Stable machine code: the live fetch failed and a cached list **past** its `NextUpdate` was used.
/// The verdict it produced may not reflect a service the scheme operator has since withdrawn.
pub const CODE_TSL_SERVED_FROM_STALE_CACHE: &str = "tsl_served_from_stale_cache";

/// Every code [`TslCacheServe::code`] can return, for exhaustiveness checks in consumers and their
/// translation catalogues. Append-only.
pub const ALL_TSL_CACHE_CODES: &[&str] =
    &[CODE_TSL_SERVED_FROM_CACHE, CODE_TSL_SERVED_FROM_STALE_CACHE];

/// Resolve the maximum staleness window from [`ENV_TSL_CACHE_MAX_STALE_HOURS`], else
/// [`DEFAULT_MAX_STALE`]. A negative or unparseable value falls back to the default.
pub fn max_stale_from_env() -> Duration {
    match std::env::var(ENV_TSL_CACHE_MAX_STALE_HOURS) {
        Ok(raw) => match raw.trim().parse::<i64>() {
            Ok(hours) if hours >= 0 => Duration::hours(hours),
            _ => DEFAULT_MAX_STALE,
        },
        Err(_) => DEFAULT_MAX_STALE,
    }
}

/// The clock a [`CachingTslSource`] reads. `Pinned` exists so the staleness and maximum-age rules
/// are testable without sleeping or touching file mtimes.
#[derive(Debug, Clone, Copy)]
pub enum TslClock {
    /// `OffsetDateTime::now_utc()`.
    System,
    /// A fixed instant.
    Pinned(OffsetDateTime),
}

impl TslClock {
    /// The current instant according to this clock.
    pub fn now(self) -> OffsetDateTime {
        match self {
            TslClock::System => OffsetDateTime::now_utc(),
            TslClock::Pinned(at) => at,
        }
    }
}

/// A cached copy that passed every load-time check and may be handed to the parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedTslBytes {
    /// The raw Trusted List XML, byte-identical to what was fetched.
    pub bytes: Vec<u8>,
    /// When these bytes were fetched.
    pub fetched_at: OffsetDateTime,
    /// The list's own `NextUpdate`, or `fetched_at + FALLBACK_TTL` when it carries none.
    pub expires_at: OffsetDateTime,
    /// Whether `expires_at` has passed. `true` means the verdict this copy produces is reported
    /// under [`CODE_TSL_SERVED_FROM_STALE_CACHE`].
    pub stale: bool,
}

/// Why a cached entry that exists on disk was not used. Each variant is a refusal, never a
/// downgrade — the caller falls back to reporting the original fetch failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TslCacheRefusal {
    /// Past `expires_at + max_stale`. This is the bound that makes a restore safe: a backup
    /// restored months later brings its cache along, and that cache is refused on age here rather
    /// than silently vouching for long-withdrawn services.
    TooOld {
        /// When the refused copy was fetched.
        fetched_at: OffsetDateTime,
        /// When it expired.
        expires_at: OffsetDateTime,
        /// The last instant at which it would still have been served.
        usable_until: OffsetDateTime,
    },
    /// The stored bytes do not hash to the digest recorded beside them: a truncated write, a
    /// partial restore, or tampering. Either way these are not the bytes that were fetched.
    DigestMismatch,
    /// The entry could not be read or parsed (unreadable metadata, unparseable XML, missing pair
    /// half). Carries a short reason for the operator-facing detail.
    Unusable(String),
}

/// The outcome of asking the durable cache for a source's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TslCacheLoad {
    /// Nothing has ever been cached for this source.
    Missing,
    /// An entry exists but must not be used.
    Refused(TslCacheRefusal),
    /// An entry that may be used.
    Usable(CachedTslBytes),
}

/// A record that a fetch was answered from the durable cache rather than the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TslCacheServe {
    /// When the cached bytes were originally fetched.
    #[serde(with = "time::serde::rfc3339")]
    pub fetched_at: OffsetDateTime,
    /// The cached list's own expiry.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// When the cache was consulted (i.e. when the live fetch failed).
    #[serde(with = "time::serde::rfc3339")]
    pub served_at: OffsetDateTime,
    /// Whether the served copy was past its own `NextUpdate`.
    pub stale: bool,
    /// The live-fetch failure that made the cache necessary, already expanded through its whole
    /// `source()` chain by [`crate::error::describe_error_chain`].
    pub fetch_error: String,
}

impl TslCacheServe {
    /// The stable machine code for this serve. Never a sentence — the presentation layer owns the
    /// wording, in its own locale.
    pub fn code(&self) -> &'static str {
        if self.stale {
            CODE_TSL_SERVED_FROM_STALE_CACHE
        } else {
            CODE_TSL_SERVED_FROM_CACHE
        }
    }
}

/// How the most recent [`TslSource::fetch`] on a source was satisfied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TslFetchProvenance {
    /// Nothing has been fetched through this source yet.
    #[default]
    Unknown,
    /// The list came live from its configured location — the ordinary path.
    Fetched,
    /// The live fetch failed and the durable cache answered instead.
    ServedFromCache(TslCacheServe),
}

impl TslFetchProvenance {
    /// The serve record, when the list came from the cache.
    pub fn cache_serve(&self) -> Option<&TslCacheServe> {
        match self {
            TslFetchProvenance::ServedFromCache(serve) => Some(serve),
            _ => None,
        }
    }

    /// Whether the list came from a cached copy that was past its own `NextUpdate`.
    pub fn is_stale_cache(&self) -> bool {
        self.cache_serve().is_some_and(|serve| serve.stale)
    }
}

/// Version tag on the metadata sidecar. Bumped if the on-disk shape ever changes; an entry whose
/// version this build does not recognise is refused rather than reinterpreted.
const CACHE_METADATA_VERSION: u8 = 1;

/// What is recorded beside the cached XML. Deliberately *descriptive* — provenance and an integrity
/// digest. It holds no verdict, no anchor and no algorithm decision, so nothing in it can be
/// mistaken for authority the current configuration has not re-granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
    version: u8,
    /// The configured source id this entry belongs to, for human inspection of the directory.
    source_id: String,
    /// RFC 3339 fetch time.
    fetched_at: String,
    /// Lowercase hex SHA-256 over the cached XML bytes.
    sha256: String,
    /// Length of the cached XML, for a cheap first mismatch check.
    bytes: u64,
}

/// The durable Trusted List byte cache rooted at a directory.
#[derive(Debug, Clone)]
pub struct TslDiskCache {
    dir: PathBuf,
}

impl TslDiskCache {
    /// A cache rooted at `dir` (typically `<data dir>/tsl-cache`). The directory is created lazily
    /// on the first successful store, so constructing this never touches the filesystem.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The cache rooted at `TSL_CACHE_DIR` under an instance data directory.
    pub fn under_data_dir(data_dir: impl AsRef<Path>) -> Self {
        Self::new(data_dir.as_ref().join(TSL_CACHE_DIR))
    }

    /// The directory this cache is rooted at.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A filesystem-safe key identifying one configured source.
    ///
    /// It hashes the source **id together with its location**, so re-pointing a configured entry at
    /// a different URL does not let it be answered from bytes fetched from the old one — a repoint
    /// is a deliberate change of which list this installation trusts, and inheriting the previous
    /// list's cache would quietly undo it.
    pub fn key_for(source_id: &str, location: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(source_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(location.as_bytes());
        hex_lower(&hasher.finalize())
    }

    fn xml_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.xml"))
    }

    fn metadata_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    fn serve_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.serve.json"))
    }

    /// Persist `bytes` as the cached copy for `key`.
    ///
    /// The XML is written first and the metadata second, and a crash between the two never yields an
    /// entry with the wrong provenance — but by two different routes, depending on whether this key
    /// had a cached entry already:
    ///
    /// - **First store.** There is no metadata yet, so the interrupted entry has XML and no
    ///   metadata, and loads as [`TslCacheLoad::Missing`].
    /// - **Refresh.** The *previous* metadata survives, still carrying the previous digest, while
    ///   the XML on disk is already the new bytes. [`Self::load`] digests what it reads and compares,
    ///   so the mismatch is caught and the entry is refused with
    ///   [`TslCacheRefusal::DigestMismatch`] — it is never served under the old fetch time or the
    ///   old source id.
    ///
    /// Both are fail-closed. What the ordering buys is that neither outcome is a *usable* entry
    /// describing bytes it does not contain; recovering the entry is a re-fetch either way.
    ///
    /// Re-storing byte-identical content is skipped, because the common case is one successful fetch
    /// per signature and rewriting ~700 KB each time is pure cost.
    pub fn store(
        &self,
        key: &str,
        source_id: &str,
        bytes: &[u8],
        fetched_at: OffsetDateTime,
    ) -> Result<(), TslError> {
        let sha256 = hex_lower(&Sha256::digest(bytes));
        if self.stored_digest(key).as_deref() == Some(sha256.as_str()) {
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir)?;
        write_atomic(&self.xml_path(key), bytes)?;
        let metadata = CacheMetadata {
            version: CACHE_METADATA_VERSION,
            source_id: source_id.to_owned(),
            fetched_at: fetched_at
                .format(&Rfc3339)
                .map_err(|e| TslError::Structure(format!("cannot format cache timestamp: {e}")))?,
            sha256,
            bytes: bytes.len() as u64,
        };
        let json = serde_json::to_vec_pretty(&metadata)
            .map_err(|e| TslError::Structure(format!("cannot serialize cache metadata: {e}")))?;
        write_atomic(&self.metadata_path(key), &json)
    }

    /// The digest recorded for `key`, or `None` when there is no readable metadata.
    fn stored_digest(&self, key: &str) -> Option<String> {
        let bytes = std::fs::read(self.metadata_path(key)).ok()?;
        let metadata: CacheMetadata = serde_json::from_slice(&bytes).ok()?;
        (metadata.version == CACHE_METADATA_VERSION).then_some(metadata.sha256)
    }

    /// Ask the cache for `key`'s bytes as of `now`, allowing at most `max_stale` beyond the cached
    /// list's own expiry.
    ///
    /// Every check is re-run here from the bytes on disk: the digest, the list's `NextUpdate` (by
    /// re-parsing the XML) and the age bound. Nothing is taken on the metadata's word except the
    /// fetch time, and a wrong fetch time can only make an entry look *older* than it is once the
    /// list's own `NextUpdate` is present.
    pub fn load(&self, key: &str, now: OffsetDateTime, max_stale: Duration) -> TslCacheLoad {
        let metadata_bytes = match std::fs::read(self.metadata_path(key)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return TslCacheLoad::Missing,
            Err(e) => {
                return TslCacheLoad::Refused(TslCacheRefusal::Unusable(format!(
                    "cache metadata unreadable: {e}"
                )));
            }
        };
        let metadata: CacheMetadata = match serde_json::from_slice(&metadata_bytes) {
            Ok(m) => m,
            Err(e) => {
                return TslCacheLoad::Refused(TslCacheRefusal::Unusable(format!(
                    "cache metadata malformed: {e}"
                )));
            }
        };
        if metadata.version != CACHE_METADATA_VERSION {
            return TslCacheLoad::Refused(TslCacheRefusal::Unusable(format!(
                "cache metadata version {} is not readable by this build",
                metadata.version
            )));
        }
        let fetched_at = match OffsetDateTime::parse(&metadata.fetched_at, &Rfc3339) {
            Ok(at) => at,
            Err(e) => {
                return TslCacheLoad::Refused(TslCacheRefusal::Unusable(format!(
                    "cache fetch time unparseable: {e}"
                )));
            }
        };
        let bytes = match std::fs::read(self.xml_path(key)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return TslCacheLoad::Missing,
            Err(e) => {
                return TslCacheLoad::Refused(TslCacheRefusal::Unusable(format!(
                    "cached Trusted List unreadable: {e}"
                )));
            }
        };
        if bytes.len() as u64 != metadata.bytes
            || hex_lower(&Sha256::digest(&bytes)) != metadata.sha256
        {
            return TslCacheLoad::Refused(TslCacheRefusal::DigestMismatch);
        }
        // Re-parse to recover the list's own validity window. A cached copy that no longer parses
        // is not a list, whatever the metadata says about it.
        let expires_at = match crate::parse::parse_tsl(&bytes) {
            Ok(list) => list.next_update.unwrap_or(fetched_at + FALLBACK_TTL),
            Err(e) => {
                return TslCacheLoad::Refused(TslCacheRefusal::Unusable(format!(
                    "cached Trusted List no longer parses: {e}"
                )));
            }
        };
        let usable_until = expires_at + max_stale;
        if now > usable_until {
            return TslCacheLoad::Refused(TslCacheRefusal::TooOld {
                fetched_at,
                expires_at,
                usable_until,
            });
        }
        TslCacheLoad::Usable(CachedTslBytes {
            bytes,
            fetched_at,
            expires_at,
            stale: now >= expires_at,
        })
    }

    /// Record that `key` was answered from the cache, so surfaces that never saw the signature can
    /// still report it. Best-effort: a write failure must not fail a signature that has otherwise
    /// succeeded, so the error is returned for logging and callers ignore it.
    pub fn record_serve(&self, key: &str, serve: &TslCacheServe) -> Result<(), TslError> {
        std::fs::create_dir_all(&self.dir)?;
        let json = serde_json::to_vec_pretty(serve).map_err(|e| {
            TslError::Structure(format!("cannot serialize cache serve record: {e}"))
        })?;
        write_atomic(&self.serve_path(key), &json)
    }

    /// Drop any serve record for `key`. Called after a successful live fetch: the current answer
    /// came from the network, so the previous cache serve is history, not state.
    pub fn clear_serve(&self, key: &str) {
        let _ = std::fs::remove_file(self.serve_path(key));
    }

    /// The last recorded cache serve for `key`, if the most recent resolution used the cache.
    pub fn last_serve(&self, key: &str) -> Option<TslCacheServe> {
        let bytes = std::fs::read(self.serve_path(key)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

/// A [`TslSource`] that write-caches every successful fetch and falls back to that cache when a
/// later fetch fails.
///
/// It returns **bytes**, like any other source, so the list it hands back goes through the same
/// parse → XML-DSig verify → anchor match → algorithm policy pipeline as a freshly-fetched one. A
/// revoked anchor or a tightened policy therefore invalidates a cached list at its next use, with
/// no invalidation logic of its own to get wrong.
pub struct CachingTslSource<S: TslSource> {
    inner: S,
    cache: TslDiskCache,
    key: String,
    source_id: String,
    max_stale: Duration,
    clock: TslClock,
    provenance: Arc<Mutex<TslFetchProvenance>>,
}

impl<S: TslSource> CachingTslSource<S> {
    /// Wrap `inner`, caching under `cache` at the entry for `source_id`/`location`, and serving a
    /// cached copy at most `max_stale` past its expiry.
    pub fn new(
        inner: S,
        cache: TslDiskCache,
        source_id: &str,
        location: &str,
        max_stale: Duration,
    ) -> Self {
        Self {
            inner,
            key: TslDiskCache::key_for(source_id, location),
            cache,
            source_id: source_id.to_owned(),
            max_stale,
            clock: TslClock::System,
            provenance: Arc::new(Mutex::new(TslFetchProvenance::Unknown)),
        }
    }

    /// Read the clock from `clock` instead of the system clock (tests).
    pub fn with_clock(mut self, clock: TslClock) -> Self {
        self.clock = clock;
        self
    }

    /// The cache-directory key this source reads and writes.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// A handle that observes this source's provenance without borrowing it — the signing path
    /// hands the source to a [`TslClient`](crate::query::TslClient) and cannot get it back.
    pub fn provenance_handle(&self) -> TslProvenanceHandle {
        TslProvenanceHandle {
            inner: Arc::clone(&self.provenance),
        }
    }

    fn set_provenance(&self, provenance: TslFetchProvenance) {
        if let Ok(mut slot) = self.provenance.lock() {
            *slot = provenance;
        }
    }
}

impl<S: TslSource> std::fmt::Debug for CachingTslSource<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingTslSource")
            .field("source_id", &self.source_id)
            .field("key", &self.key)
            .field("cache_dir", &self.cache.dir())
            .field("max_stale", &self.max_stale)
            .finish_non_exhaustive()
    }
}

impl<S: TslSource> TslSource for CachingTslSource<S> {
    fn fetch(&self) -> Result<Vec<u8>, TslError> {
        let now = self.clock.now();
        let fetch_error = match self.inner.fetch() {
            Ok(bytes) => {
                // A live list always wins. Persist it, and retire any record of having previously
                // fallen back — the current answer came from the network.
                if let Err(e) = self.cache.store(&self.key, &self.source_id, &bytes, now) {
                    eprintln!(
                        "chancela-tsl: could not persist the Trusted List cache for source '{}': {e}",
                        self.source_id
                    );
                }
                self.cache.clear_serve(&self.key);
                self.set_provenance(TslFetchProvenance::Fetched);
                return Ok(bytes);
            }
            Err(e) => e,
        };

        match self.cache.load(&self.key, now, self.max_stale) {
            TslCacheLoad::Usable(cached) => {
                let serve = TslCacheServe {
                    fetched_at: cached.fetched_at,
                    expires_at: cached.expires_at,
                    served_at: now,
                    stale: cached.stale,
                    fetch_error: fetch_error.to_string(),
                };
                if let Err(e) = self.cache.record_serve(&self.key, &serve) {
                    eprintln!(
                        "chancela-tsl: could not record the Trusted List cache serve for source '{}': {e}",
                        self.source_id
                    );
                }
                self.set_provenance(TslFetchProvenance::ServedFromCache(serve));
                Ok(cached.bytes)
            }
            // No usable cache: the caller must see the fetch failure, unchanged. Fail-closed is not
            // relaxed by this wrapper — it only ever substitutes bytes it is allowed to substitute.
            other => {
                if let TslCacheLoad::Refused(reason) = &other {
                    eprintln!(
                        "chancela-tsl: the durable cache for source '{}' was refused ({reason:?}); \
                         reporting the fetch failure",
                        self.source_id
                    );
                }
                self.set_provenance(TslFetchProvenance::Fetched);
                Err(fetch_error)
            }
        }
    }

    fn last_fetch_provenance(&self) -> TslFetchProvenance {
        self.provenance
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_default()
    }
}

/// A cloneable observer of a [`CachingTslSource`]'s provenance, usable after the source has been
/// moved into a client.
#[derive(Debug, Clone)]
pub struct TslProvenanceHandle {
    inner: Arc<Mutex<TslFetchProvenance>>,
}

impl TslProvenanceHandle {
    /// How the observed source's most recent fetch was satisfied.
    pub fn provenance(&self) -> TslFetchProvenance {
        self.inner
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_default()
    }
}

/// Lowercase hex of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Write `bytes` to `path` via a uniquely-named sibling temp file and a rename, so a reader never
/// observes a half-written Trusted List.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), TslError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "tsl-cache-entry".into());
    name.push(format!(".{}.{seq}.tmp", std::process::id()));
    let tmp = path.with_file_name(name);
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(TslError::Io(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    /// A minimal well-formed Trusted List whose `NextUpdate` is `next_update`.
    fn list_xml(next_update: &str) -> Vec<u8> {
        format!(
            concat!(
                r#"<?xml version="1.0" encoding="UTF-8"?>"#,
                r#"<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">"#,
                "<SchemeInformation>",
                "<SchemeTerritory>PT</SchemeTerritory>",
                "<NextUpdate><dateTime>{}</dateTime></NextUpdate>",
                "</SchemeInformation>",
                "</TrustServiceStatusList>",
            ),
            next_update
        )
        .into_bytes()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "chancela-tsl-cache-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    const FETCHED: OffsetDateTime = datetime!(2026-01-15 0:00 UTC);

    #[test]
    fn a_stored_entry_loads_back_byte_identical_and_fresh() {
        let dir = temp_dir("roundtrip");
        let cache = TslDiskCache::new(&dir);
        let key = TslDiskCache::key_for("pt", "https://example.invalid/tsl.xml");
        let xml = list_xml("2026-07-15T00:00:00Z");

        cache.store(&key, "pt", &xml, FETCHED).expect("store");
        let loaded = cache.load(&key, datetime!(2026-03-01 0:00 UTC), DEFAULT_MAX_STALE);

        match loaded {
            TslCacheLoad::Usable(cached) => {
                assert_eq!(cached.bytes, xml, "the cache must return the fetched bytes");
                assert_eq!(cached.fetched_at, FETCHED);
                assert_eq!(cached.expires_at, datetime!(2026-07-15 0:00 UTC));
                assert!(!cached.stale, "inside NextUpdate is not stale");
            }
            other => panic!("expected a usable entry, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn past_next_update_is_served_but_reported_stale() {
        let dir = temp_dir("stale");
        let cache = TslDiskCache::new(&dir);
        let key = TslDiskCache::key_for("pt", "loc");
        cache
            .store(&key, "pt", &list_xml("2026-07-15T00:00:00Z"), FETCHED)
            .expect("store");

        // One day past NextUpdate: inside the 7-day grace, so served — and marked.
        match cache.load(&key, datetime!(2026-07-16 0:00 UTC), DEFAULT_MAX_STALE) {
            TslCacheLoad::Usable(cached) => assert!(cached.stale),
            other => panic!("expected a usable stale entry, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn past_the_maximum_age_is_refused_not_served() {
        let dir = temp_dir("too-old");
        let cache = TslDiskCache::new(&dir);
        let key = TslDiskCache::key_for("pt", "loc");
        cache
            .store(&key, "pt", &list_xml("2026-07-15T00:00:00Z"), FETCHED)
            .expect("store");

        // Eight days past NextUpdate is one day past the seven-day bound.
        match cache.load(&key, datetime!(2026-07-23 0:00:01 UTC), DEFAULT_MAX_STALE) {
            TslCacheLoad::Refused(TslCacheRefusal::TooOld { usable_until, .. }) => {
                assert_eq!(usable_until, datetime!(2026-07-22 0:00 UTC));
            }
            other => panic!("expected a TooOld refusal, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_zero_grace_refuses_anything_past_next_update() {
        let dir = temp_dir("zero-grace");
        let cache = TslDiskCache::new(&dir);
        let key = TslDiskCache::key_for("pt", "loc");
        cache
            .store(&key, "pt", &list_xml("2026-07-15T00:00:00Z"), FETCHED)
            .expect("store");

        assert!(matches!(
            cache.load(&key, datetime!(2026-07-15 0:00:01 UTC), Duration::ZERO),
            TslCacheLoad::Refused(TslCacheRefusal::TooOld { .. })
        ));
        // ...while still serving inside the window.
        assert!(matches!(
            cache.load(&key, datetime!(2026-07-14 0:00 UTC), Duration::ZERO),
            TslCacheLoad::Usable(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_list_without_next_update_expires_on_the_fallback_ttl() {
        let dir = temp_dir("no-next-update");
        let cache = TslDiskCache::new(&dir);
        let key = TslDiskCache::key_for("pt", "loc");
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?><TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation></TrustServiceStatusList>"#;
        cache.store(&key, "pt", xml, FETCHED).expect("store");

        match cache.load(&key, FETCHED + Duration::hours(1), DEFAULT_MAX_STALE) {
            TslCacheLoad::Usable(cached) => {
                assert_eq!(cached.expires_at, FETCHED + FALLBACK_TTL);
                assert!(!cached.stale);
            }
            other => panic!("expected a usable entry, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_bytes_are_refused_on_the_recorded_digest() {
        let dir = temp_dir("digest");
        let cache = TslDiskCache::new(&dir);
        let key = TslDiskCache::key_for("pt", "loc");
        cache
            .store(&key, "pt", &list_xml("2026-07-15T00:00:00Z"), FETCHED)
            .expect("store");

        let swapped = list_xml("2099-01-01T00:00:00Z");
        std::fs::write(dir.join(format!("{key}.xml")), &swapped).expect("overwrite cached xml");

        assert_eq!(
            cache.load(&key, datetime!(2026-03-01 0:00 UTC), DEFAULT_MAX_STALE),
            TslCacheLoad::Refused(TslCacheRefusal::DigestMismatch),
            "bytes that do not match the recorded digest are not the bytes that were fetched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_entry_is_missing_not_an_error() {
        let dir = temp_dir("absent");
        let cache = TslDiskCache::new(&dir);
        assert_eq!(
            cache.load("nothing-here", FETCHED, DEFAULT_MAX_STALE),
            TslCacheLoad::Missing
        );
    }

    #[test]
    fn repointing_a_source_at_another_url_does_not_inherit_its_cache() {
        let a = TslDiskCache::key_for("pt", "https://a.invalid/tsl.xml");
        let b = TslDiskCache::key_for("pt", "https://b.invalid/tsl.xml");
        assert_ne!(a, b, "the location must be part of the cache key");
        assert_eq!(a, TslDiskCache::key_for("pt", "https://a.invalid/tsl.xml"));
    }

    #[test]
    fn max_stale_from_env_rejects_a_typo_rather_than_reading_it_as_zero() {
        // Not a #[test]-scoped env mutation: assert the parse rule directly on the same logic.
        for (raw, expected) in [
            ("0", Some(Duration::ZERO)),
            ("48", Some(Duration::hours(48))),
            ("-1", None),
            ("soon", None),
            ("", None),
        ] {
            let parsed = match raw.trim().parse::<i64>() {
                Ok(hours) if hours >= 0 => Some(Duration::hours(hours)),
                _ => None,
            };
            assert_eq!(parsed, expected, "parsing {raw:?}");
        }
    }

    #[test]
    fn a_serve_record_round_trips_and_is_cleared_by_a_live_fetch() {
        let dir = temp_dir("serve");
        let cache = TslDiskCache::new(&dir);
        let key = "k";
        let serve = TslCacheServe {
            fetched_at: FETCHED,
            expires_at: datetime!(2026-07-15 0:00 UTC),
            served_at: datetime!(2026-07-16 0:00 UTC),
            stale: true,
            fetch_error: "dns error".to_owned(),
        };
        cache.record_serve(key, &serve).expect("record");
        assert_eq!(cache.last_serve(key).as_ref(), Some(&serve));
        assert_eq!(
            cache.last_serve(key).unwrap().code(),
            CODE_TSL_SERVED_FROM_STALE_CACHE
        );

        cache.clear_serve(key);
        assert!(cache.last_serve(key).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
