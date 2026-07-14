//! **wp16 Phase 3a — cluster-shared session state, global rate-limits, and cross-node cache
//! coherence for session/permission changes.**
//!
//! P0–P2 gave us a single-writer leader, a follower change-feed, and write-redirect. But three
//! pieces of *auth* state were still per-process `HashMap`s (`lib.rs` `sessions`, `signin_backoff`,
//! …). In a multi-node cluster those become genuinely shared state (plan §5.3):
//!
//! - a **session** minted on the leader must be recognised on a follower;
//! - **sign-in backoff / rate-limits** must be *global*, or an attacker gets `N×` the attempts by
//!   spraying across `N` nodes — a **security** requirement in multi-node, not an optimization;
//! - a **session revoke / role change** on one node must invalidate the relevant cached state on the
//!   others (plan §5.2).
//!
//! This module is the honest, feature-gated home for all three. Everything here is **inert by
//! default**: the [`Default`] backend of every abstraction is a *local-only no-op* that defers
//! entirely to the existing in-memory maps, so **single-node behaviour is byte-identical to today**.
//! Only when the crate is built with the `redis` feature **and** `REDIS_URL` / `REDIS_URL_FILE` is
//! set does a Redis-backed impl take over and make the state cluster-wide.
//!
//! # Fail-modes (deliberate, documented, not accidental)
//!
//! - **Sessions → FAIL-CLOSED.** A session that cannot be verified against the shared store (Redis
//!   down / errored) is treated as *unauthenticated* ([`SessionLookup::Unavailable`]), never granted
//!   access on a miss or a backend error. Authentication never fails *open*. Compare this to the
//!   cache-aside layer ([`crate::cache`]), which is deliberately fail-*open* — that is safe because a
//!   stale cache entry cannot forge authority, whereas a fail-open session lookup would.
//! - **Rate-limits → FAIL-CLOSED / conservative.** If the shared counter is unreachable
//!   ([`RateLimitOutcome::Unavailable`]) we do **not** silently reset to "unlimited attempts": the
//!   caller keeps its existing per-node backoff as a floor. The shared counter can only ever make the
//!   throttle *stricter* (global), never looser.
//!
//! # The node-local signing key stays node-local (plan §5.3)
//!
//! The in-memory `sessions` map entry can hold a *decrypted* attestation signing key for the session
//! lifetime. That key **must never** leave the process. So the shared [`SessionStore`] carries only
//! the session **identity + expiry** (`token → user_id`, with TTL); the unlocked key remains in the
//! node-local `sessions` map on the authenticating node, and attestation signing stays pinned there.
//! A follower resolving a leader-minted session gets a valid *actor identity* (it can act on behalf
//! of the user) but not the unlocked key — exactly the split the plan calls for.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

// ============================================================================================
// Session store
// ============================================================================================

/// The result of a shared-store session lookup. The three "not a hit" arms are kept distinct
/// because they mean different things to the caller (and to security):
///
/// - [`NotShared`](SessionLookup::NotShared) — there is no shared store (single-node no-op); the
///   caller falls back **entirely** to its node-local map, so behaviour is byte-identical to today.
/// - [`NotFound`](SessionLookup::NotFound) — the shared store answered authoritatively that this
///   token is unknown / expired ⇒ unauthenticated.
/// - [`Unavailable`](SessionLookup::Unavailable) — **FAIL-CLOSED**: the shared store errored / was
///   unreachable, so the token *cannot be verified* ⇒ treated as unauthenticated. Never a hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionLookup {
    /// No shared store is active — defer to the node-local map (single-node byte-identical path).
    NotShared,
    /// The shared store holds a live session for this token.
    Found {
        /// The principal the token authenticates.
        user_id: Uuid,
    },
    /// The shared store authoritatively has no live session for this token.
    NotFound,
    /// FAIL-CLOSED: the shared store could not be consulted — treat as unauthenticated.
    Unavailable,
}

/// A cluster-shared session identity store (`token → user_id`, with expiry). **Identity + expiry
/// only** — never the unlocked signing key (see the module docs).
///
/// The [`Default`]/local impl is a no-op: [`SessionStore::resolve`] returns
/// [`SessionLookup::NotShared`] so the caller uses its node-local map unchanged. Only the Redis impl
/// makes sessions cluster-wide.
pub trait SessionStore: Send + Sync + fmt::Debug {
    /// Record `token → user_id` with a TTL. Best-effort for the shared layer (the node-local map is
    /// the authority on the minting node); errors are swallowed after logging.
    fn put(&self, token: &str, user_id: Uuid, ttl: Duration);
    /// Resolve `token`, sliding its TTL forward by `ttl` on a hit. **FAIL-CLOSED** on any backend
    /// error ([`SessionLookup::Unavailable`]).
    fn resolve(&self, token: &str, ttl: Duration) -> SessionLookup;
    /// Revoke `token` cluster-wide (so a follower stops recognising it). Best-effort.
    fn revoke(&self, token: &str);
    /// A short label for logs / diagnostics (`"local"`, `"redis"`).
    fn kind(&self) -> &'static str;
}

/// The default session store: a pure no-op. Every `resolve` returns [`SessionLookup::NotShared`], so
/// the caller falls back to its node-local `sessions` map and single-node behaviour is unchanged.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalOnlySessionStore;

impl SessionStore for LocalOnlySessionStore {
    fn put(&self, _token: &str, _user_id: Uuid, _ttl: Duration) {}
    fn resolve(&self, _token: &str, _ttl: Duration) -> SessionLookup {
        SessionLookup::NotShared
    }
    fn revoke(&self, _token: &str) {}
    fn kind(&self) -> &'static str {
        "local"
    }
}

/// A shared handle to the active [`SessionStore`]. Newtype over `Arc<dyn SessionStore>` so
/// [`AppState`](crate::AppState) keeps deriving `Default` (⇒ [`LocalOnlySessionStore`]) and `Clone`.
#[derive(Clone, Debug)]
pub struct SharedSessionStore(pub Arc<dyn SessionStore>);

impl Default for SharedSessionStore {
    fn default() -> Self {
        SharedSessionStore(Arc::new(LocalOnlySessionStore))
    }
}

impl std::ops::Deref for SharedSessionStore {
    type Target = dyn SessionStore;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl SharedSessionStore {
    /// Wrap any concrete [`SessionStore`].
    pub fn new(store: impl SessionStore + 'static) -> Self {
        SharedSessionStore(Arc::new(store))
    }
}

// ============================================================================================
// Global rate-limit / sign-in backoff
// ============================================================================================

/// The result of peeking / recording against the shared rate-limit counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitOutcome {
    /// No shared counter is active — the caller's node-local backoff is the sole authority
    /// (single-node byte-identical path).
    NotShared,
    /// The current global failure count within the window for this key.
    Count(u32),
    /// FAIL-CLOSED / conservative: the shared counter could not be consulted. The caller must keep
    /// its node-local backoff as a floor and must **not** reset to unlimited.
    Unavailable,
}

/// A cluster-shared, atomic failure counter for sign-in backoff / rate-limits. Global across nodes
/// so an attacker cannot bypass a throttle by hitting a different node (plan §5.3).
///
/// The [`Default`]/local impl is a no-op returning [`RateLimitOutcome::NotShared`], so the node-local
/// backoff stays the sole authority and single-node behaviour is unchanged.
pub trait RateLimiter: Send + Sync + fmt::Debug {
    /// Increment the failure counter for `key`, (re)arming a `window` TTL, and return the new global
    /// count. On a backend error returns [`RateLimitOutcome::Unavailable`] (the failure could not be
    /// recorded globally; the caller's local counter still advances).
    fn record_failure(&self, key: &str, window: Duration) -> RateLimitOutcome;
    /// Read the current global failure count for `key` without incrementing. **FAIL-CLOSED**:
    /// a backend error returns [`RateLimitOutcome::Unavailable`], never `Count(0)`.
    fn peek(&self, key: &str) -> RateLimitOutcome;
    /// Clear the counter for `key` (e.g. after a successful sign-in). Best-effort.
    fn clear(&self, key: &str);
    /// A short label for logs / diagnostics (`"local"`, `"redis"`).
    fn kind(&self) -> &'static str;
}

/// The maximum number of global failures within the window before the shared limiter blocks. A
/// coarse cluster-wide cap layered *above* the per-node escalating backoff; deliberately generous so
/// it only ever catches a cross-node spray, never a single user's honest retries on one node.
pub const GLOBAL_SIGNIN_FAILURE_CAP: u32 = 50;

/// Whether a shared global count should block the attempt (fail-closed on `Unavailable` is decided by
/// the caller, which keeps its local floor). Pure so it is unit-tested without a backend.
pub fn global_limit_blocks(outcome: &RateLimitOutcome, cap: u32) -> bool {
    matches!(outcome, RateLimitOutcome::Count(n) if *n >= cap)
}

/// The default rate limiter: a pure no-op. Every op is [`RateLimitOutcome::NotShared`], so the
/// node-local backoff is unchanged.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalOnlyRateLimiter;

impl RateLimiter for LocalOnlyRateLimiter {
    fn record_failure(&self, _key: &str, _window: Duration) -> RateLimitOutcome {
        RateLimitOutcome::NotShared
    }
    fn peek(&self, _key: &str) -> RateLimitOutcome {
        RateLimitOutcome::NotShared
    }
    fn clear(&self, _key: &str) {}
    fn kind(&self) -> &'static str {
        "local"
    }
}

/// A shared handle to the active [`RateLimiter`]. Newtype so [`AppState`](crate::AppState) keeps
/// deriving `Default` (⇒ [`LocalOnlyRateLimiter`]) and `Clone`.
#[derive(Clone, Debug)]
pub struct SharedRateLimiter(pub Arc<dyn RateLimiter>);

impl Default for SharedRateLimiter {
    fn default() -> Self {
        SharedRateLimiter(Arc::new(LocalOnlyRateLimiter))
    }
}

impl std::ops::Deref for SharedRateLimiter {
    type Target = dyn RateLimiter;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl SharedRateLimiter {
    /// Wrap any concrete [`RateLimiter`].
    pub fn new(limiter: impl RateLimiter + 'static) -> Self {
        SharedRateLimiter(Arc::new(limiter))
    }
}

// ============================================================================================
// Cross-node cache / session invalidation (plan §5.2)
// ============================================================================================

/// A cross-node invalidation signal one node publishes so the others drop the corresponding cached
/// state. Session revocation is already correct across nodes via the shared [`SessionStore`] (a
/// `revoke` DEL makes a follower's `resolve` miss); this bus additionally lets a node evict the
/// **node-local** copy (which still holds the unlocked key) and refresh permission-derived caches for
/// changes that are *not* ledger events (role/delegation edits live in file sidecars, so the P1
/// change-feed does not carry them — plan §8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationEvent {
    /// A session was revoked (signed out / expired-and-dropped). Other nodes should evict any
    /// node-local copy of `token`.
    SessionRevoked {
        /// The revoked opaque session token.
        token: String,
    },
    /// A user's roles / delegations changed. Other nodes should drop any permission-derived cache
    /// for `user_id` (and, conservatively, the shared catalog projections).
    RoleChanged {
        /// The affected principal.
        user_id: Uuid,
    },
}

impl InvalidationEvent {
    /// The stable wire payload published on the pub/sub channel.
    pub fn encode(&self) -> String {
        match self {
            InvalidationEvent::SessionRevoked { token } => format!("session-revoked:{token}"),
            InvalidationEvent::RoleChanged { user_id } => format!("role-changed:{user_id}"),
        }
    }

    /// Parse a wire payload back into an event; `None` for an unrecognised / malformed message (an
    /// unknown message is ignored, never a hard error — forward-compatible with newer publishers).
    pub fn parse(payload: &str) -> Option<Self> {
        if let Some(token) = payload.strip_prefix("session-revoked:") {
            let token = token.trim();
            return (!token.is_empty()).then(|| InvalidationEvent::SessionRevoked {
                token: token.to_owned(),
            });
        }
        if let Some(uid) = payload.strip_prefix("role-changed:") {
            return Uuid::parse_str(uid.trim())
                .ok()
                .map(|user_id| InvalidationEvent::RoleChanged { user_id });
        }
        None
    }
}

/// A cross-node invalidation publisher. The [`Default`]/local impl is a no-op (single-node needs no
/// cross-node signalling); the Redis impl `PUBLISH`es on a shared channel.
pub trait InvalidationBus: Send + Sync + fmt::Debug {
    /// Publish `event` to the other nodes. Best-effort: a publish failure is swallowed after logging
    /// (a missed signal degrades to "the other node's cache lapses on its own TTL / next reconcile",
    /// never to incorrectness — the authoritative check is always the shared store / in-memory state).
    fn publish(&self, event: &InvalidationEvent);
    /// The DSN a subscriber should connect to in order to receive events, or `None` for the local
    /// no-op bus (so no listener is spawned on single-node).
    fn subscribe_dsn(&self) -> Option<String>;
    /// A short label for logs / diagnostics (`"local"`, `"redis"`).
    fn kind(&self) -> &'static str;
}

/// The default invalidation bus: a pure no-op (single-node).
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalOnlyInvalidationBus;

impl InvalidationBus for LocalOnlyInvalidationBus {
    fn publish(&self, _event: &InvalidationEvent) {}
    fn subscribe_dsn(&self) -> Option<String> {
        None
    }
    fn kind(&self) -> &'static str {
        "local"
    }
}

/// A shared handle to the active [`InvalidationBus`]. Newtype so [`AppState`](crate::AppState) keeps
/// deriving `Default` (⇒ [`LocalOnlyInvalidationBus`]) and `Clone`.
#[derive(Clone, Debug)]
pub struct SharedInvalidationBus(pub Arc<dyn InvalidationBus>);

impl Default for SharedInvalidationBus {
    fn default() -> Self {
        SharedInvalidationBus(Arc::new(LocalOnlyInvalidationBus))
    }
}

impl std::ops::Deref for SharedInvalidationBus {
    type Target = dyn InvalidationBus;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl SharedInvalidationBus {
    /// Wrap any concrete [`InvalidationBus`].
    pub fn new(bus: impl InvalidationBus + 'static) -> Self {
        SharedInvalidationBus(Arc::new(bus))
    }
}

/// The Redis pub/sub channel session/permission invalidations are broadcast on.
pub const INVALIDATION_CHANNEL: &str = "chancela:v1:invalidate";

impl crate::AppState {
    /// Apply a received cross-node [`InvalidationEvent`] to this node's local state (plan §5.2):
    /// evict the node-local session copy for a revoke, drop the shared catalog projection for a role
    /// change. Fail-open by nature: doing nothing on an unknown/duplicate event is safe (the
    /// authoritative check is always the shared store / in-memory state).
    pub(crate) async fn apply_invalidation(&self, event: &InvalidationEvent) {
        match event {
            InvalidationEvent::SessionRevoked { token } => {
                self.sessions.write().await.remove(token);
            }
            InvalidationEvent::RoleChanged { .. } => {
                // Permission grants are derived from the role catalog + delegation table (file
                // sidecars) each request, so there is no per-user permission memo to purge here; we
                // conservatively drop the shared catalog projection so any permission-shaped cached
                // read recomputes. Kept minimal on purpose.
                self.cache.invalidate(&crate::cache::CacheKey::CaeCatalog);
            }
        }
    }
}

// ============================================================================================
// Environment resolution + construction
// ============================================================================================

/// Resolve `REDIS_URL_FILE` (docker secret; wins) then `REDIS_URL`, trimming and treating blank as
/// unset. Mirrors the `cache` module's resolver. Only referenced under the `redis` feature.
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
            Err(e) => eprintln!(
                "cluster shared-state: REDIS_URL_FILE is set but unreadable ({e}); ignoring it"
            ),
        }
    }
    std::env::var("REDIS_URL")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The resolved shared-state backends: sessions, rate-limits, and the invalidation bus. All three
/// default to their local no-op, so an [`AppState`](crate::AppState) that never calls
/// [`from_env`](SharedClusterState::from_env) is byte-identical to today.
#[derive(Clone, Debug, Default)]
pub struct SharedClusterState {
    /// The shared session identity store.
    pub sessions: SharedSessionStore,
    /// The shared sign-in / rate-limit counter.
    pub signin_limiter: SharedRateLimiter,
    /// The cross-node invalidation bus.
    pub invalidation: SharedInvalidationBus,
}

impl SharedClusterState {
    /// Resolve the shared-state backends from the environment. With the `redis` feature built **and**
    /// `REDIS_URL` / `REDIS_URL_FILE` set, all three become Redis-backed (cluster-wide sessions +
    /// global rate-limits + pub/sub invalidation). Otherwise every backend stays its local no-op and
    /// single-node behaviour is unchanged. A malformed URL logs and falls back to the no-op.
    pub fn from_env() -> Self {
        #[cfg(feature = "redis")]
        {
            if let Some(url) = redis_url_from_env() {
                match redis_backed::RedisClusterState::connect(&url) {
                    Ok(state) => {
                        eprintln!(
                            "cluster shared-state: Redis-backed sessions + GLOBAL sign-in \
                             rate-limits + cross-node invalidation ENABLED (REDIS_URL configured). \
                             Sessions are cluster-wide and FAIL-CLOSED on a Redis outage; rate-limits \
                             are global and fail-closed to the per-node backoff floor."
                        );
                        return Self {
                            sessions: SharedSessionStore::new(state.sessions()),
                            signin_limiter: SharedRateLimiter::new(state.limiter()),
                            invalidation: SharedInvalidationBus::new(state.bus(url)),
                        };
                    }
                    Err(e) => eprintln!(
                        "cluster shared-state: REDIS_URL is set but the Redis client failed to \
                         initialise ({e}); continuing with per-node in-memory session/limit state"
                    ),
                }
            }
        }
        Self::default()
    }
}

// ============================================================================================
// Optional Redis backend (off-by-default `redis` feature)
// ============================================================================================

#[cfg(feature = "redis")]
mod redis_backed {
    use std::time::Duration;

    use uuid::Uuid;

    use super::{
        INVALIDATION_CHANNEL, InvalidationBus, InvalidationEvent, RateLimitOutcome, RateLimiter,
        SessionLookup, SessionStore,
    };

    /// Bound on how long any single op may block on the network, so a slow/unreachable Redis fails
    /// closed *fast* (a session lookup that times out is `Unavailable` ⇒ unauthenticated) rather than
    /// stalling a request.
    const OP_TIMEOUT: Duration = Duration::from_millis(200);

    /// Namespaced Redis keys, versioned so multiple app versions can share one Redis safely.
    fn session_key(token: &str) -> String {
        format!("chancela:v1:session:{token}")
    }
    fn ratelimit_key(key: &str) -> String {
        format!("chancela:v1:ratelimit:{key}")
    }

    fn log(context: &str, e: redis::RedisError) {
        eprintln!("cluster shared-state(redis): {context}: {e}");
    }

    /// A cloneable Redis client shared by the three shared-state backends (one client, lazy conns).
    #[derive(Clone)]
    pub(super) struct RedisClusterState {
        client: redis::Client,
    }

    impl RedisClusterState {
        /// Build a client for `url`. Errors only on a malformed URL; a well-formed-but-unreachable URL
        /// constructs fine (connections are lazy — the fail-closed timeout applies per op).
        pub(super) fn connect(url: &str) -> Result<Self, redis::RedisError> {
            Ok(Self {
                client: redis::Client::open(url)?,
            })
        }

        /// Run `op` against a fresh, timeout-bounded connection. Returns `Err(())` on ANY connection
        /// or command error (already logged) so each caller can pick its own fail-mode: sessions map
        /// this to fail-closed `Unavailable`, best-effort ops swallow it.
        fn with_conn<T>(
            &self,
            context: &str,
            op: impl FnOnce(&mut redis::Connection) -> redis::RedisResult<T>,
        ) -> Result<T, ()> {
            let mut conn = self
                .client
                .get_connection_with_timeout(OP_TIMEOUT)
                .map_err(|e| log(context, e))?;
            let _ = conn.set_read_timeout(Some(OP_TIMEOUT));
            let _ = conn.set_write_timeout(Some(OP_TIMEOUT));
            op(&mut conn).map_err(|e| log(context, e))
        }

        pub(super) fn sessions(&self) -> RedisSessionStore {
            RedisSessionStore(self.clone())
        }
        pub(super) fn limiter(&self) -> RedisRateLimiter {
            RedisRateLimiter(self.clone())
        }
        pub(super) fn bus(&self, url: String) -> RedisInvalidationBus {
            RedisInvalidationBus {
                inner: self.clone(),
                url,
            }
        }
    }

    /// Redis-backed shared session identity store (token → user_id, with TTL).
    #[derive(Clone)]
    pub(super) struct RedisSessionStore(RedisClusterState);

    impl std::fmt::Debug for RedisSessionStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RedisSessionStore").finish_non_exhaustive()
        }
    }

    impl SessionStore for RedisSessionStore {
        fn put(&self, token: &str, user_id: Uuid, ttl: Duration) {
            let secs = ttl.as_secs().max(1);
            let _ = self.0.with_conn("session put", |conn| {
                redis::cmd("SET")
                    .arg(session_key(token))
                    .arg(user_id.to_string())
                    .arg("EX")
                    .arg(secs)
                    .query::<()>(conn)
            });
        }

        fn resolve(&self, token: &str, ttl: Duration) -> SessionLookup {
            // FAIL-CLOSED: a connection/command error is `Unavailable`, NOT a miss that could be
            // retried as open. Only an authoritative nil reply is `NotFound`.
            let value: Option<String> = match self.0.with_conn("session resolve", |conn| {
                redis::cmd("GET")
                    .arg(session_key(token))
                    .query::<Option<String>>(conn)
            }) {
                Ok(v) => v,
                Err(()) => return SessionLookup::Unavailable,
            };
            match value.as_deref().map(str::trim).map(Uuid::parse_str) {
                Some(Ok(user_id)) => {
                    // Slide the TTL forward on a hit (best-effort; a failure here does not un-auth).
                    let secs = ttl.as_secs().max(1);
                    let _ = self.0.with_conn("session slide", |conn| {
                        redis::cmd("EXPIRE")
                            .arg(session_key(token))
                            .arg(secs)
                            .query::<()>(conn)
                    });
                    SessionLookup::Found { user_id }
                }
                // A stored-but-unparseable value is corrupt ⇒ fail-closed rather than trust it.
                Some(Err(_)) => SessionLookup::Unavailable,
                None => SessionLookup::NotFound,
            }
        }

        fn revoke(&self, token: &str) {
            let _ = self.0.with_conn("session revoke", |conn| {
                redis::cmd("DEL").arg(session_key(token)).query::<()>(conn)
            });
        }

        fn kind(&self) -> &'static str {
            "redis"
        }
    }

    /// Redis-backed global failure counter (atomic `INCR` + `EXPIRE` window).
    #[derive(Clone)]
    pub(super) struct RedisRateLimiter(RedisClusterState);

    impl std::fmt::Debug for RedisRateLimiter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RedisRateLimiter").finish_non_exhaustive()
        }
    }

    impl RateLimiter for RedisRateLimiter {
        fn record_failure(&self, key: &str, window: Duration) -> RateLimitOutcome {
            let secs = window.as_secs().max(1);
            let result = self.0.with_conn("ratelimit incr", |conn| {
                // INCR is atomic and returns the new value; arm the window TTL on the first failure
                // (NX so a later failure never *extends* a window that is already counting down).
                let count: i64 = redis::cmd("INCR").arg(ratelimit_key(key)).query(conn)?;
                if count == 1 {
                    redis::cmd("EXPIRE")
                        .arg(ratelimit_key(key))
                        .arg(secs)
                        .query::<()>(conn)?;
                }
                Ok(count.max(0) as u32)
            });
            match result {
                Ok(count) => RateLimitOutcome::Count(count),
                Err(()) => RateLimitOutcome::Unavailable,
            }
        }

        fn peek(&self, key: &str) -> RateLimitOutcome {
            match self.0.with_conn("ratelimit peek", |conn| {
                redis::cmd("GET")
                    .arg(ratelimit_key(key))
                    .query::<Option<i64>>(conn)
            }) {
                Ok(Some(count)) => RateLimitOutcome::Count(count.max(0) as u32),
                Ok(None) => RateLimitOutcome::Count(0),
                // FAIL-CLOSED: an error is `Unavailable`, never `Count(0)` (which would look "clean").
                Err(()) => RateLimitOutcome::Unavailable,
            }
        }

        fn clear(&self, key: &str) {
            let _ = self.0.with_conn("ratelimit clear", |conn| {
                redis::cmd("DEL").arg(ratelimit_key(key)).query::<()>(conn)
            });
        }

        fn kind(&self) -> &'static str {
            "redis"
        }
    }

    /// Redis-backed cross-node invalidation bus (`PUBLISH` on [`INVALIDATION_CHANNEL`]).
    #[derive(Clone)]
    pub(super) struct RedisInvalidationBus {
        inner: RedisClusterState,
        url: String,
    }

    impl std::fmt::Debug for RedisInvalidationBus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RedisInvalidationBus")
                .finish_non_exhaustive()
        }
    }

    impl InvalidationBus for RedisInvalidationBus {
        fn publish(&self, event: &InvalidationEvent) {
            let _ = self.inner.with_conn("invalidation publish", |conn| {
                redis::cmd("PUBLISH")
                    .arg(INVALIDATION_CHANNEL)
                    .arg(event.encode())
                    .query::<()>(conn)
            });
        }

        fn subscribe_dsn(&self) -> Option<String> {
            Some(self.url.clone())
        }

        fn kind(&self) -> &'static str {
            "redis"
        }
    }
}

// ============================================================================================
// Cross-node invalidation subscriber (spawned in `app`)
// ============================================================================================

/// Mount the cross-node invalidation subscriber as a background task. No-op unless a Redis
/// invalidation bus is active (i.e. `redis` feature + `REDIS_URL`); the default single-node build
/// spawns nothing. Must be called from within the server's tokio runtime.
#[cfg(feature = "redis")]
pub(crate) fn spawn_invalidation_listener(state: crate::AppState) {
    let Some(dsn) = state.cluster_shared.invalidation.subscribe_dsn() else {
        return;
    };
    eprintln!(
        "cluster shared-state: subscribing to '{INVALIDATION_CHANNEL}' for cross-node session/role \
         invalidation"
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InvalidationEvent>(64);
    std::thread::spawn(move || invalidation_listen_thread(dsn, tx));
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            state.apply_invalidation(&event).await;
        }
    });
}

/// The no-op subscriber on builds without the `redis` feature.
#[cfg(not(feature = "redis"))]
pub(crate) fn spawn_invalidation_listener(_state: crate::AppState) {}

/// The dedicated blocking Redis `SUBSCRIBE` listener: forwards each decoded [`InvalidationEvent`] to
/// the async applier. Reconnects on error; a dropped subscription only loses the acceleration (caches
/// still lapse on their own TTL / the shared store stays authoritative), never correctness.
#[cfg(feature = "redis")]
fn invalidation_listen_thread(dsn: String, tx: tokio::sync::mpsc::Sender<InvalidationEvent>) {
    loop {
        if tx.is_closed() {
            return;
        }
        let mut conn = match redis::Client::open(dsn.as_str())
            .and_then(|client| client.get_connection())
        {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!(
                    "cluster shared-state: invalidation SUBSCRIBE connect failed ({e}); retrying in 2s"
                );
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let mut pubsub = conn.as_pubsub();
        if let Err(e) = pubsub.subscribe(INVALIDATION_CHANNEL) {
            eprintln!(
                "cluster shared-state: SUBSCRIBE {INVALIDATION_CHANNEL} failed ({e}); retrying"
            );
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        let _ = pubsub.set_read_timeout(Some(Duration::from_secs(5)));
        loop {
            if tx.is_closed() {
                return;
            }
            let msg = match pubsub.get_message() {
                Ok(msg) => msg,
                // A read timeout is normal (lets us re-check `tx.is_closed()`); other errors reconnect.
                Err(e) if e.is_timeout() => continue,
                Err(_) => break,
            };
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Some(event) = InvalidationEvent::parse(&payload) {
                if tx.blocking_send(event).is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Session store: the in-memory default behaves exactly as today ────────────────────────────

    #[test]
    fn local_session_store_is_a_noop_defer_to_local_map() {
        let store = LocalOnlySessionStore;
        assert_eq!(store.kind(), "local");
        let uid = Uuid::new_v4();
        // put / revoke are no-ops; resolve always says "not shared" so the caller uses its local map
        // — byte-identical to today's single-node behaviour.
        store.put("tok", uid, Duration::from_secs(60));
        assert_eq!(
            store.resolve("tok", Duration::from_secs(60)),
            SessionLookup::NotShared
        );
        store.revoke("tok");
        assert_eq!(
            store.resolve("tok", Duration::from_secs(60)),
            SessionLookup::NotShared
        );
    }

    #[test]
    fn shared_session_store_defaults_to_local_noop() {
        let shared = SharedSessionStore::default();
        assert_eq!(shared.kind(), "local");
        assert_eq!(
            shared.resolve("x", Duration::from_secs(1)),
            SessionLookup::NotShared
        );
    }

    /// A test-double shared session store standing in for a live Redis "node": create on one handle
    /// is visible from another handle over the same shared map. Proves the cross-node contract the
    /// Redis impl provides, without a server.
    #[derive(Debug, Clone, Default)]
    struct FakeSharedSessions {
        map: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Uuid>>>,
    }
    impl SessionStore for FakeSharedSessions {
        fn put(&self, token: &str, user_id: Uuid, _ttl: Duration) {
            self.map.lock().unwrap().insert(token.to_owned(), user_id);
        }
        fn resolve(&self, token: &str, _ttl: Duration) -> SessionLookup {
            match self.map.lock().unwrap().get(token) {
                Some(user_id) => SessionLookup::Found { user_id: *user_id },
                None => SessionLookup::NotFound,
            }
        }
        fn revoke(&self, token: &str) {
            self.map.lock().unwrap().remove(token);
        }
        fn kind(&self) -> &'static str {
            "fake"
        }
    }

    #[test]
    fn shared_session_visible_across_nodes_and_revoke_is_cluster_wide() {
        // Two handles over the SAME shared backend simulate two nodes pointed at one Redis.
        let node_a = FakeSharedSessions::default();
        let node_b = node_a.clone();
        let uid = Uuid::new_v4();

        // Node A mints a session.
        node_a.put("tok", uid, Duration::from_secs(60));
        // Node B recognises it (session minted on the leader valid on a follower).
        assert_eq!(
            node_b.resolve("tok", Duration::from_secs(60)),
            SessionLookup::Found { user_id: uid }
        );
        // Node A revokes → cluster-wide: node B no longer recognises it.
        node_a.revoke("tok");
        assert_eq!(
            node_b.resolve("tok", Duration::from_secs(60)),
            SessionLookup::NotFound
        );
    }

    /// A shared session store whose backend always errors — the fail-closed contract.
    #[derive(Debug)]
    struct FailingSessions;
    impl SessionStore for FailingSessions {
        fn put(&self, _t: &str, _u: Uuid, _ttl: Duration) {}
        fn resolve(&self, _t: &str, _ttl: Duration) -> SessionLookup {
            SessionLookup::Unavailable
        }
        fn revoke(&self, _t: &str) {}
        fn kind(&self) -> &'static str {
            "failing"
        }
    }

    #[test]
    fn session_lookup_fails_closed_on_backend_error() {
        // The core security property: a session that cannot be VERIFIED (backend error) is
        // `Unavailable` — the caller must treat it as unauthenticated, NEVER grant access.
        let store = FailingSessions;
        assert_eq!(
            store.resolve("tok", Duration::from_secs(60)),
            SessionLookup::Unavailable,
        );
        // `Unavailable` is deliberately NOT `Found`: it can never authenticate.
        assert!(!matches!(
            store.resolve("tok", Duration::from_secs(60)),
            SessionLookup::Found { .. }
        ));
    }

    // ── Rate-limit: shared counter increments across nodes; fail-closed fallback ──────────────────

    #[test]
    fn local_rate_limiter_is_a_noop() {
        let limiter = LocalOnlyRateLimiter;
        assert_eq!(limiter.kind(), "local");
        assert_eq!(
            limiter.record_failure("k", Duration::from_secs(60)),
            RateLimitOutcome::NotShared
        );
        assert_eq!(limiter.peek("k"), RateLimitOutcome::NotShared);
    }

    /// A test-double shared counter shared across "nodes".
    #[derive(Debug, Clone, Default)]
    struct FakeSharedCounter {
        map: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>,
    }
    impl RateLimiter for FakeSharedCounter {
        fn record_failure(&self, key: &str, _window: Duration) -> RateLimitOutcome {
            let mut map = self.map.lock().unwrap();
            let count = map.entry(key.to_owned()).or_insert(0);
            *count += 1;
            RateLimitOutcome::Count(*count)
        }
        fn peek(&self, key: &str) -> RateLimitOutcome {
            RateLimitOutcome::Count(self.map.lock().unwrap().get(key).copied().unwrap_or(0))
        }
        fn clear(&self, key: &str) {
            self.map.lock().unwrap().remove(key);
        }
        fn kind(&self) -> &'static str {
            "fake"
        }
    }

    #[test]
    fn shared_counter_increments_across_simulated_nodes() {
        let node_a = FakeSharedCounter::default();
        let node_b = node_a.clone();
        // Failures on DIFFERENT nodes accrue against the SAME global counter — an attacker cannot get
        // N× the attempts by spraying across nodes.
        assert_eq!(
            node_a.record_failure("user:1", Duration::from_secs(60)),
            RateLimitOutcome::Count(1)
        );
        assert_eq!(
            node_b.record_failure("user:1", Duration::from_secs(60)),
            RateLimitOutcome::Count(2)
        );
        assert_eq!(node_a.peek("user:1"), RateLimitOutcome::Count(2));
        // A successful sign-in clears the global counter.
        node_b.clear("user:1");
        assert_eq!(node_a.peek("user:1"), RateLimitOutcome::Count(0));
    }

    #[test]
    fn global_limit_blocks_at_or_above_cap_only() {
        assert!(!global_limit_blocks(&RateLimitOutcome::Count(49), 50));
        assert!(global_limit_blocks(&RateLimitOutcome::Count(50), 50));
        assert!(global_limit_blocks(&RateLimitOutcome::Count(51), 50));
        // NotShared / Unavailable never block on their own — the caller keeps its local floor.
        assert!(!global_limit_blocks(&RateLimitOutcome::NotShared, 50));
        assert!(!global_limit_blocks(&RateLimitOutcome::Unavailable, 50));
    }

    /// A shared counter whose backend always errors.
    #[derive(Debug)]
    struct FailingCounter;
    impl RateLimiter for FailingCounter {
        fn record_failure(&self, _key: &str, _window: Duration) -> RateLimitOutcome {
            RateLimitOutcome::Unavailable
        }
        fn peek(&self, _key: &str) -> RateLimitOutcome {
            RateLimitOutcome::Unavailable
        }
        fn clear(&self, _key: &str) {}
        fn kind(&self) -> &'static str {
            "failing"
        }
    }

    #[test]
    fn rate_limit_fails_closed_not_to_unlimited() {
        // When the shared counter is unreachable, peek is `Unavailable` — NOT `Count(0)`. So the
        // limiter never *resets to unlimited*; the caller falls back to its per-node backoff floor.
        let limiter = FailingCounter;
        assert_eq!(limiter.peek("k"), RateLimitOutcome::Unavailable);
        assert!(!global_limit_blocks(&limiter.peek("k"), 50));
        // Crucially, `Unavailable` is distinguishable from a clean `Count(0)`, so the caller can keep
        // the local floor rather than believe the user is clean.
        assert_ne!(limiter.peek("k"), RateLimitOutcome::Count(0));
    }

    // ── Invalidation: encode/parse round-trip + apply classification ─────────────────────────────

    #[test]
    fn invalidation_event_encode_parse_round_trip() {
        let uid = Uuid::new_v4();
        for event in [
            InvalidationEvent::SessionRevoked {
                token: "abc-123".to_owned(),
            },
            InvalidationEvent::RoleChanged { user_id: uid },
        ] {
            let wire = event.encode();
            assert_eq!(
                InvalidationEvent::parse(&wire),
                Some(event),
                "wire payload {wire:?} must round-trip"
            );
        }
    }

    #[test]
    fn invalidation_parse_rejects_garbage_and_empty() {
        assert_eq!(InvalidationEvent::parse("nonsense"), None);
        assert_eq!(InvalidationEvent::parse("session-revoked:"), None);
        assert_eq!(InvalidationEvent::parse("role-changed:not-a-uuid"), None);
        assert_eq!(InvalidationEvent::parse(""), None);
    }

    /// A recording invalidation bus proving a revoke/role-change signal is published for other nodes
    /// to consume (the pub/sub is mocked; a live-Redis fan-out is the `#[ignore]` test below).
    #[derive(Debug, Default)]
    struct RecordingBus {
        published: std::sync::Mutex<Vec<InvalidationEvent>>,
    }
    impl InvalidationBus for RecordingBus {
        fn publish(&self, event: &InvalidationEvent) {
            self.published.lock().unwrap().push(event.clone());
        }
        fn subscribe_dsn(&self) -> Option<String> {
            None
        }
        fn kind(&self) -> &'static str {
            "recording"
        }
    }

    #[test]
    fn revoke_and_role_change_are_published_for_other_nodes() {
        let bus = RecordingBus::default();
        let uid = Uuid::new_v4();
        bus.publish(&InvalidationEvent::SessionRevoked {
            token: "tok".to_owned(),
        });
        bus.publish(&InvalidationEvent::RoleChanged { user_id: uid });
        let published = bus.published.lock().unwrap();
        assert_eq!(published.len(), 2);
        assert_eq!(
            published[0],
            InvalidationEvent::SessionRevoked {
                token: "tok".to_owned()
            }
        );
        assert_eq!(
            published[1],
            InvalidationEvent::RoleChanged { user_id: uid }
        );
    }

    #[test]
    fn shared_cluster_state_defaults_are_all_local_noops() {
        // The single-node default: every backend is its local no-op, so the app is byte-identical.
        let state = SharedClusterState::default();
        assert_eq!(state.sessions.kind(), "local");
        assert_eq!(state.signin_limiter.kind(), "local");
        assert_eq!(state.invalidation.kind(), "local");
        assert!(state.invalidation.subscribe_dsn().is_none());
    }

    // ── Live-Redis round-trips (§5.2/§5.3) ───────────────────────────────────────────────────────
    //
    // These exercise the real Redis wiring. They are `#[ignore]` so the offline suite never needs a
    // server; run them with REDIS_URL:
    //   REDIS_URL=redis://127.0.0.1:6379 cargo test -p chancela-api --features redis -- --ignored
    #[cfg(feature = "redis")]
    mod live {
        use super::*;

        fn live_state() -> Option<SharedClusterState> {
            let url = std::env::var("REDIS_URL").ok().filter(|s| !s.is_empty())?;
            // Two independent `from_env`-style builds over the same URL simulate two nodes.
            unsafe {
                std::env::set_var("REDIS_URL", &url);
            }
            Some(SharedClusterState::from_env())
        }

        #[test]
        #[ignore = "requires a live Redis (set REDIS_URL)"]
        fn redis_session_visible_on_a_second_node_and_revoke_is_cluster_wide() {
            let Some(node_a) = live_state() else { return };
            let node_b = SharedClusterState::from_env();
            assert_eq!(node_a.sessions.kind(), "redis");

            let token = format!("wp16-p3a-{}", Uuid::new_v4());
            let uid = Uuid::new_v4();
            let ttl = Duration::from_secs(60);

            // Minted on "node A".
            node_a.sessions.put(&token, uid, ttl);
            // Visible on "node B" (a session minted on the leader is recognised on a follower).
            assert_eq!(
                node_b.sessions.resolve(&token, ttl),
                SessionLookup::Found { user_id: uid }
            );
            // Delete revokes cluster-wide.
            node_a.sessions.revoke(&token);
            assert_eq!(
                node_b.sessions.resolve(&token, ttl),
                SessionLookup::NotFound
            );
        }

        #[test]
        #[ignore = "requires a live Redis (set REDIS_URL)"]
        fn redis_rate_limit_counter_is_global() {
            let Some(node_a) = live_state() else { return };
            let node_b = SharedClusterState::from_env();
            let key = format!("wp16-p3a-rl-{}", Uuid::new_v4());
            let window = Duration::from_secs(30);

            node_a.signin_limiter.clear(&key);
            let a = node_a.signin_limiter.record_failure(&key, window);
            let b = node_b.signin_limiter.record_failure(&key, window);
            assert_eq!(a, RateLimitOutcome::Count(1));
            assert_eq!(
                b,
                RateLimitOutcome::Count(2),
                "counter is global across nodes"
            );
            node_a.signin_limiter.clear(&key);
        }
    }
}
