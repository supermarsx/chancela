//! wp14 Phase 4 — an optional, honestly-scoped caching layer.
//!
//! # Honest scope (read this first)
//!
//! Chancela is **in-memory-authoritative**: every domain read is served from the
//! `Arc<RwLock<..>>` collections in [`AppState`](crate::AppState), *not* from a database. A
//! network cache in front of RAM therefore has almost no single-node value. Two things here are
//! worth doing, and **only one of them is a real single-node speed-up**:
//!
//! 1. **The in-process `Ledger::verify()` memo ([`VerifyMemo`]) — the genuine single-node win.**
//!    The dashboard and the `GET /v1/ledger/verify` probe walk the *entire* hash chain (`O(n)`)
//!    on every call. [`VerifyMemo`] caches that verdict keyed by the ledger **head hash + length**,
//!    so a repeat verification over an unchanged chain is `O(1)`. It lives strictly in-process
//!    (backed by `moka`, no Redis): the input already lives in RAM and the verdict is tiny, so a
//!    network hop would be *slower* than recomputing. Invalidation is automatic — a new append
//!    changes the head, which changes the key. Verify **semantics are unchanged**; the memo is a
//!    transparent cache over [`chancela_ledger::Ledger::verify`].
//!
//! 2. **The optional Redis cache-aside ([`RedisCache`], behind the off-by-default `redis` Cargo
//!    feature).** Cache-aside for a couple of read-heavy, rarely-mutated catalog projections (today:
//!    the CAE catalog metadata). This is **not** a single-node performance fix — those reads are
//!    already RAM-served; its real purpose is a **shared** cache for a future *multi-instance*
//!    deployment. It is completely inert unless the crate is built with `redis` **and** `REDIS_URL`
//!    is set. Every call site is **fail-open**: a Redis miss or error is swallowed (logged) and the
//!    caller falls through to the authoritative in-memory state — a cache error **never** fails a
//!    request.
//!
//! The default [`Cache`] is [`NullCache`], a pure no-op: the application behaves **identically**
//! with the cache absent, disabled, or failing.
//!
//! ## Configuration
//!
//! - `REDIS_URL` — e.g. `redis://redis:6379`. Absent (or the `redis` feature off) ⇒ [`NullCache`].
//! - `REDIS_URL_FILE` — docker-secret indirection (a file whose contents are the URL); takes
//!   precedence over `REDIS_URL`, mirroring `CHANCELA_DB_KEY_FILE`.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use axum::response::{IntoResponse, Response};
use chancela_ledger::Ledger;

/// The maximum number of `(head, len)` verdicts [`VerifyMemo`] retains. A tiny window (the current
/// head plus a few recent ones) is plenty: only the live head is ever queried on the hot path.
const VERIFY_MEMO_CAPACITY: u64 = 8;

/// The maximum number of cache-aside entries the in-process [`MokaCache`] retains.
const MOKA_CACHE_CAPACITY: u64 = 1024;

/// A namespaced, typed cache key for the optional cache-aside layer. Keeping the key set small and
/// explicit (rather than free-form strings) makes every cached surface auditable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheKey {
    /// The active CAE catalog metadata projection (the no-search form of `GET /v1/cae`). Rarely
    /// mutated: only a successful `POST /v1/cae/refresh` supersede swaps the catalog.
    CaeCatalog,
    /// Per-act generated-document metadata list, keyed by act id. Genuinely DB-bound; invalidated
    /// on the owning act's document upsert. (Available for reuse; exercised by tests.)
    ActDocuments(String),
}

impl CacheKey {
    /// The stable, namespaced Redis key string. The version segment lets multiple app versions
    /// share one Redis without colliding on an incompatible payload shape.
    pub fn redis_key(&self) -> String {
        match self {
            CacheKey::CaeCatalog => "chancela:v1:cae:catalog".to_owned(),
            CacheKey::ActDocuments(id) => format!("chancela:v1:act-documents:{id}"),
        }
    }
}

/// A cache-aside store for a small set of typed read models.
///
/// Every method is **fail-open**: an unconfigured, disabled, or failing backend behaves as a
/// miss / no-op so the caller falls back to the authoritative in-memory state. The trait is
/// **synchronous** so it is callable identically from the async handlers and any synchronous path.
pub trait Cache: Send + Sync + fmt::Debug {
    /// Fetch the cached bytes for `key`, or `None` on a miss **or any backend error** (fail-open).
    fn get(&self, key: &CacheKey) -> Option<Vec<u8>>;
    /// Populate `key` with `value` under a TTL. Best-effort: errors are swallowed.
    fn set(&self, key: &CacheKey, value: &[u8], ttl: Duration);
    /// Drop `key` (invalidation on mutation). Best-effort: errors are swallowed.
    fn invalidate(&self, key: &CacheKey);
    /// A short label for logs / diagnostics (`"null"`, `"moka"`, `"redis"`).
    fn kind(&self) -> &'static str;
}

/// The default cache: a pure no-op. Every `get` misses; `set`/`invalidate` do nothing. With
/// `NullCache` the application is byte-for-byte identical to having no cache at all.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullCache;

impl Cache for NullCache {
    fn get(&self, _key: &CacheKey) -> Option<Vec<u8>> {
        None
    }
    fn set(&self, _key: &CacheKey, _value: &[u8], _ttl: Duration) {}
    fn invalidate(&self, _key: &CacheKey) {}
    fn kind(&self) -> &'static str {
        "null"
    }
}

/// An in-process cache-aside backed by `moka`. Available without any feature — a single-node cache
/// for the same rarely-mutated projections with **no network hop**. Per-entry TTL is honoured by
/// stamping each value with an expiry `Instant` and treating an elapsed entry as a miss; `moka`
/// bounds the total entry count. Cloning shares the one underlying cache (moka is internally `Arc`).
#[derive(Clone)]
pub struct MokaCache {
    inner: moka::sync::Cache<String, (std::time::Instant, Vec<u8>)>,
}

impl fmt::Debug for MokaCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MokaCache")
            .field("entries", &self.inner.entry_count())
            .finish()
    }
}

impl Default for MokaCache {
    fn default() -> Self {
        Self::new()
    }
}

impl MokaCache {
    /// Build an empty in-process cache bounded to [`MOKA_CACHE_CAPACITY`] entries.
    pub fn new() -> Self {
        Self {
            inner: moka::sync::Cache::builder()
                .max_capacity(MOKA_CACHE_CAPACITY)
                .build(),
        }
    }
}

impl Cache for MokaCache {
    fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let (expires_at, value) = self.inner.get(&key.redis_key())?;
        if expires_at <= std::time::Instant::now() {
            // Lazily drop the expired entry so a later `set` starts a fresh TTL.
            self.inner.invalidate(&key.redis_key());
            return None;
        }
        Some(value)
    }
    fn set(&self, key: &CacheKey, value: &[u8], ttl: Duration) {
        let expires_at = std::time::Instant::now() + ttl;
        self.inner
            .insert(key.redis_key(), (expires_at, value.to_vec()));
    }
    fn invalidate(&self, key: &CacheKey) {
        self.inner.invalidate(&key.redis_key());
    }
    fn kind(&self) -> &'static str {
        "moka"
    }
}

/// The in-process memo of [`chancela_ledger::Ledger::verify`] — the real single-node cache win.
///
/// Caches the `O(n)` chain-verify verdict keyed by `(head hash, length)`, so repeat verifications
/// over an unchanged chain are `O(1)`. The key uniquely identifies the in-process chain state:
/// within a running process the event vector only ever grows (append changes the head) or is
/// wholesale-replaced (restore / re-anchor changes the head), so a matching `(head, len)` always
/// denotes the same chain — the memo can never serve a stale verdict for a mutated chain.
///
/// The verdict is stored as `Result<u64, String>` (the error rendered to an owned string so it is
/// `Clone`-able and cacheable) — exactly the information the call sites need. Backed by `moka`;
/// cloning shares the one underlying cache.
/// The memo key: the ledger head hash (`None` for an empty ledger) plus its length.
type VerifyKey = (Option<[u8; 32]>, usize);
/// The memoized verdict: `Ok(len)` for an intact chain, `Err(reason)` for a broken one (the error
/// rendered to an owned string so it is `Clone`-able and cacheable).
type VerifyVerdict = Result<u64, String>;

#[derive(Clone)]
pub struct VerifyMemo {
    inner: moka::sync::Cache<VerifyKey, VerifyVerdict>,
}

impl fmt::Debug for VerifyMemo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyMemo")
            .field("entries", &self.inner.entry_count())
            .finish()
    }
}

impl Default for VerifyMemo {
    fn default() -> Self {
        Self {
            inner: moka::sync::Cache::builder()
                .max_capacity(VERIFY_MEMO_CAPACITY)
                .build(),
        }
    }
}

impl VerifyMemo {
    /// The transparent memo of [`Ledger::verify`]: return the cached verdict for the ledger's
    /// current head, computing and memoizing it on a miss. The result is `Ok(len)` for an intact
    /// chain or `Err(reason)` for a broken one — the same verdict `Ledger::verify()` yields, with
    /// the error rendered to a string.
    pub fn verdict(&self, ledger: &Ledger) -> Result<u64, String> {
        let key = (ledger.head(), ledger.len());
        if let Some(cached) = self.inner.get(&key) {
            return cached;
        }
        let verdict = ledger.verify().map_err(|e| e.to_string());
        self.inner.insert(key, verdict.clone());
        verdict
    }

    /// Test seam: overwrite the memoized verdict for the ledger's current head with a sentinel, so
    /// a subsequent `verdict()` that returns the sentinel proves the cache was consulted (rather
    /// than recomputed).
    #[cfg(test)]
    fn poison_current(&self, ledger: &Ledger, verdict: Result<u64, String>) {
        self.inner.insert((ledger.head(), ledger.len()), verdict);
    }
}

/// A shared handle to the active [`Cache`]. A newtype over `Arc<dyn Cache>` so [`AppState`] can keep
/// deriving `Default` (default ⇒ [`NullCache`]) and `Clone` (a cheap `Arc` clone shares the one
/// backend). Derefs to `dyn Cache`, so `state.cache.get(..)` reads through transparently.
#[derive(Clone, Debug)]
pub struct SharedCache(pub Arc<dyn Cache>);

impl Default for SharedCache {
    fn default() -> Self {
        SharedCache(Arc::new(NullCache))
    }
}

impl SharedCache {
    /// The no-op cache (explicit constructor, same as [`Default`]).
    pub fn null() -> Self {
        Self::default()
    }

    /// Wrap any concrete [`Cache`] implementation.
    pub fn new(cache: impl Cache + 'static) -> Self {
        SharedCache(Arc::new(cache))
    }

    /// Resolve the cache backend from the environment. Precedence:
    ///
    /// 1. `REDIS_URL` / `REDIS_URL_FILE` (only when built with the `redis` feature) ⇒ [`RedisCache`]
    ///    — the shared, forward-looking multi-instance cache. A malformed URL logs and falls through.
    /// 2. `CHANCELA_CACHE=moka` ⇒ [`MokaCache`] — an in-process cache-aside (no network, no feature),
    ///    a modest single-node option that avoids re-serializing the cached projection on a hit.
    /// 3. Otherwise ⇒ [`NullCache`] (the default) — completely inert.
    pub fn from_env() -> Self {
        #[cfg(feature = "redis")]
        {
            if let Some(url) = redis_url_from_env() {
                match RedisCache::connect(&url) {
                    Ok(cache) => {
                        eprintln!(
                            "cache: optional Redis cache-aside ENABLED (REDIS_URL configured). \
                             Note: single-node reads are RAM-served; this is primarily a shared \
                             cache for future multi-instance use."
                        );
                        return SharedCache::new(cache);
                    }
                    Err(e) => eprintln!(
                        "cache: REDIS_URL is set but the Redis client failed to initialise ({e}); \
                         continuing with the no-op NullCache (the app is unaffected)"
                    ),
                }
            }
        }
        if matches!(
            std::env::var("CHANCELA_CACHE")
                .ok()
                .as_deref()
                .map(str::trim),
            Some("moka")
        ) {
            eprintln!("cache: in-process moka cache-aside ENABLED (CHANCELA_CACHE=moka)");
            return SharedCache::new(MokaCache::new());
        }
        SharedCache::null()
    }
}

impl std::ops::Deref for SharedCache {
    type Target = dyn Cache;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

/// Resolve `REDIS_URL_FILE` (docker secret; wins) then `REDIS_URL`, trimming and treating blank as
/// unset. Only referenced under the `redis` feature.
#[cfg(feature = "redis")]
fn redis_url_from_env() -> Option<String> {
    if let Some(path) = std::env::var_os("REDIS_URL_FILE") {
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let trimmed = contents.trim().to_owned();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
            Err(e) => eprintln!("cache: REDIS_URL_FILE is set but unreadable ({e}); ignoring it"),
        }
    }
    std::env::var("REDIS_URL")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Build a pre-serialized `application/json` response from cached bytes. Lets a cache-aside call
/// site return a hit **without** deserializing (the bytes are already the JSON body), so a
/// serialize-only response DTO can still be cached.
pub fn json_bytes_response(bytes: Vec<u8>) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response()
}

// --- Optional Redis backend (off-by-default `redis` feature) --------------------------------

#[cfg(feature = "redis")]
pub use redis_backed::RedisCache;

#[cfg(feature = "redis")]
mod redis_backed {
    use std::time::Duration;

    use super::{Cache, CacheKey};

    /// Bound on how long any single cache op may block on the network, so a slow or unreachable
    /// Redis degrades to a fast miss/no-op rather than stalling a request.
    const OP_TIMEOUT: Duration = Duration::from_millis(200);

    /// A synchronous Redis cache-aside (behind the off-by-default `redis` feature).
    ///
    /// **Fail-open by construction:** a well-formed but unreachable `REDIS_URL` still builds (the
    /// client is lazy); every operation is bounded by [`OP_TIMEOUT`] and any connection or command
    /// error is swallowed (logged) and treated as a miss / no-op. The application is therefore
    /// fully correct with Redis down, misconfigured, or absent.
    #[derive(Clone)]
    pub struct RedisCache {
        client: redis::Client,
    }

    impl std::fmt::Debug for RedisCache {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RedisCache").finish_non_exhaustive()
        }
    }

    impl RedisCache {
        /// Build a client for `url` (e.g. `redis://redis:6379`). Errors only on a malformed URL; a
        /// well-formed-but-unreachable URL constructs fine (connections are lazy + fail-open).
        pub fn connect(url: &str) -> Result<Self, redis::RedisError> {
            Ok(Self {
                client: redis::Client::open(url)?,
            })
        }

        /// Run `op` against a fresh, timeout-bounded connection, mapping every error to `None`
        /// after logging — the fail-open primitive every trait method funnels through.
        fn with_conn<T>(
            &self,
            op: impl FnOnce(&mut redis::Connection) -> redis::RedisResult<T>,
        ) -> Option<T> {
            let mut conn = self
                .client
                .get_connection_with_timeout(OP_TIMEOUT)
                .map_err(log_and_drop)
                .ok()?;
            let _ = conn.set_read_timeout(Some(OP_TIMEOUT));
            let _ = conn.set_write_timeout(Some(OP_TIMEOUT));
            op(&mut conn).map_err(log_and_drop).ok()
        }
    }

    fn log_and_drop(e: redis::RedisError) {
        eprintln!(
            "cache(redis): {e}; falling through to the authoritative in-memory state (request unaffected)"
        );
    }

    impl Cache for RedisCache {
        fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
            self.with_conn(|conn| {
                redis::cmd("GET")
                    .arg(key.redis_key())
                    .query::<Option<Vec<u8>>>(conn)
            })
            .flatten()
        }

        fn set(&self, key: &CacheKey, value: &[u8], ttl: Duration) {
            // SET key value EX <secs>; a sub-second TTL rounds up to 1s (Redis EX is whole seconds).
            let secs = ttl.as_secs().max(1);
            let _ = self.with_conn(|conn| {
                redis::cmd("SET")
                    .arg(key.redis_key())
                    .arg(value)
                    .arg("EX")
                    .arg(secs)
                    .query::<()>(conn)
            });
        }

        fn invalidate(&self, key: &CacheKey) {
            let _ = self.with_conn(|conn| redis::cmd("DEL").arg(key.redis_key()).query::<()>(conn));
        }

        fn kind(&self) -> &'static str {
            "redis"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_ledger::Ledger;

    #[test]
    fn null_cache_is_inert() {
        let cache = NullCache;
        let key = CacheKey::CaeCatalog;
        assert_eq!(cache.kind(), "null");
        assert!(cache.get(&key).is_none(), "NullCache always misses");
        // set + invalidate are no-ops and must never observably change a subsequent get.
        cache.set(&key, b"ignored", Duration::from_secs(60));
        cache.invalidate(&key);
        assert!(cache.get(&key).is_none(), "NullCache never stores anything");
    }

    #[test]
    fn verify_memo_returns_cached_verdict_until_head_changes_then_recomputes() {
        let memo = VerifyMemo::default();
        let mut ledger = Ledger::new();

        // Empty chain: the memo agrees with a direct verify() (Ok(0)).
        assert_eq!(memo.verdict(&ledger), Ok(0));

        ledger.append("api", "test", "test.event", None, b"{}");
        assert_eq!(memo.verdict(&ledger), Ok(1));

        // Prove the SECOND call is served from cache, not recomputed: poison the memoized verdict
        // for the current head with a sentinel, then observe the sentinel come back unchanged.
        memo.poison_current(&ledger, Err("SENTINEL".to_owned()));
        assert_eq!(
            memo.verdict(&ledger),
            Err("SENTINEL".to_owned()),
            "an unchanged head must return the cached verdict verbatim"
        );

        // Appending changes the head → the sentinel key no longer matches → the memo recomputes to
        // the fresh, correct verdict (never the stale sentinel).
        ledger.append("api", "test", "test.event", None, b"{}");
        assert_eq!(
            memo.verdict(&ledger),
            Ok(2),
            "a new head must recompute the verdict, not serve the stale one"
        );
    }

    #[test]
    fn verify_memo_matches_verify_for_a_multi_event_chain() {
        let memo = VerifyMemo::default();
        let mut ledger = Ledger::new();
        for _ in 0..5 {
            ledger.append("api", "test", "test.event", None, b"{}");
        }
        // The memo is transparent: its verdict equals a direct verify() (both Ok(5) here).
        assert_eq!(
            memo.verdict(&ledger),
            ledger.verify().map_err(|e| e.to_string())
        );
    }

    #[test]
    fn moka_cache_aside_populates_on_miss_and_invalidates_on_mutation() {
        let cache = MokaCache::new();
        let key = CacheKey::CaeCatalog;
        assert_eq!(cache.kind(), "moka");

        // Miss → the cache-aside call site computes and populates.
        assert!(cache.get(&key).is_none());
        cache.set(&key, b"catalog-projection-v1", Duration::from_secs(300));

        // Hit → served from cache.
        assert_eq!(
            cache.get(&key).as_deref(),
            Some(&b"catalog-projection-v1"[..])
        );

        // Mutation (e.g. a CAE refresh supersede) invalidates → next read is a miss (recompute).
        cache.invalidate(&key);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn moka_cache_respects_ttl() {
        let cache = MokaCache::new();
        let key = CacheKey::ActDocuments("act-1".to_owned());
        // A zero TTL is already expired on read → treated as a miss.
        cache.set(&key, b"stale", Duration::from_secs(0));
        assert!(
            cache.get(&key).is_none(),
            "an entry past its TTL must read as a miss"
        );
    }

    /// A test double that simulates a Redis backend whose every operation fails: `get` returns
    /// `None` (the swallowed-error contract) and `set`/`invalidate` are no-ops. It stands in for a
    /// down / unreachable Redis so we can assert the cache-aside contract without a live server.
    #[derive(Debug)]
    struct AlwaysFailingCache;
    impl Cache for AlwaysFailingCache {
        fn get(&self, _key: &CacheKey) -> Option<Vec<u8>> {
            None
        }
        fn set(&self, _key: &CacheKey, _value: &[u8], _ttl: Duration) {}
        fn invalidate(&self, _key: &CacheKey) {}
        fn kind(&self) -> &'static str {
            "always-failing"
        }
    }

    /// The generic cache-aside call shape every wired surface uses: hit ⇒ return cached bytes;
    /// miss/error ⇒ compute from the authoritative source, populate, and return.
    fn cache_aside(
        cache: &dyn Cache,
        key: &CacheKey,
        mut compute: impl FnMut() -> Vec<u8>,
    ) -> Vec<u8> {
        if let Some(hit) = cache.get(key) {
            return hit;
        }
        let value = compute();
        cache.set(key, &value, Duration::from_secs(60));
        value
    }

    #[test]
    fn cache_aside_is_fail_open_when_the_backend_always_fails() {
        let cache = AlwaysFailingCache;
        let key = CacheKey::CaeCatalog;
        let mut computed = 0u32;
        // With the backend failing every op, the cache-aside must ALWAYS fall through to compute —
        // never erroring, always returning the authoritative value.
        for _ in 0..3 {
            let value = cache_aside(&cache, &key, || {
                computed += 1;
                b"authoritative".to_vec()
            });
            assert_eq!(value, b"authoritative");
        }
        assert_eq!(
            computed, 3,
            "a failing (Redis) backend must fall through to compute every time (fail-open)"
        );
    }

    #[test]
    fn shared_cache_defaults_to_null() {
        let shared = SharedCache::default();
        assert_eq!(shared.kind(), "null");
        assert!(shared.get(&CacheKey::CaeCatalog).is_none());
    }

    #[test]
    fn shared_cache_derefs_to_wrapped_backend() {
        let shared = SharedCache::new(MokaCache::new());
        assert_eq!(shared.kind(), "moka");
        let key = CacheKey::CaeCatalog;
        shared.set(&key, b"v", Duration::from_secs(60));
        assert_eq!(shared.get(&key).as_deref(), Some(&b"v"[..]));
    }

    #[test]
    fn json_bytes_response_is_application_json() {
        let resp = json_bytes_response(b"{\"ok\":true}".to_vec());
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }
}
