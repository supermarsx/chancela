//! `chancela-ledger` — an append-only, **natively multi-chain**, hash-chained event ledger.
//!
//! This crate is the integrity backbone required by the Chancela spec:
//!
//! - **DAT-10** — every meaningful mutation generates a ledger event carrying actor,
//!   justification, timestamp, entity scope, prior event hash, and payload digest.
//! - **DAT-11 / ARC-12** — cryptographic hash chains are maintained **per company, per book,
//!   and globally**, so that tampering with either the *sequence* or the *content* of events is
//!   detectable at every level, and a company/book chain can be verified in isolation.
//! - **WFL-11 / DAT-04** — the sealed *termo de abertura* **is the genesis event** of a book's
//!   hash chain (a checked invariant: a `book:` chain's seq-0 event must be `book.opened`).
//! - **ARC-11/12** — every chain is recomputable and independently verifiable.
//!
//! # The native multi-chain model
//!
//! An event is **first-class multi-chain**. The **global** chain is the primary spine every
//! event shares — its position and linkage are the event's top-level [`Event::seq`],
//! [`Event::prev_hash`] and [`Event::hash`]. In addition, each event carries a list of
//! [`ChainLink`]s ([`Event::links`]) — one per **non-global** chain it also belongs to, each
//! with that chain's own sequence and backward hash link. There are four chain kinds
//! ([`ChainId`]): the implicit `global`, the **application-audit** chain (`application`), and
//! one **book-action** chain per `company:{uuid}` and per `book:{uuid}`.
//!
//! Chain membership is a **total, pure derivation** from an event's `scope` (and, by the frozen
//! grammar, its `kind`) — see [`Ledger::memberships`]. The application-audit chain and the
//! book-action chains are genuinely disjoint: an entity/book/act event is never in
//! `application`, and an application event is never in a company/book chain.
//!
//! # Single hash preimage
//!
//! There is **one** clean hash preimage; the event's single `hash` commits to its content, its
//! global linkage, **and** every per-chain link. `hash` is `sha256` over the concatenation, in
//! this exact order, of:
//!
//! ```text
//! prev_hash              (32 bytes)          # global backward link
//! seq                    ( 8 bytes, big-endian u64)  # global position
//! actor                  (UTF-8)  ‖ 0x1F
//! scope                  (UTF-8)  ‖ 0x1F
//! kind                   (UTF-8)  ‖ 0x1F
//! timestamp              (RFC 3339 UTF-8)  ‖ 0x1F
//! payload_digest         (32 bytes)
//! 0x1E                                       # links-section separator (ASCII record separator)
//! for each link, ordered by chain id ascending:
//!     chain_id (UTF-8)  ‖ 0x1F  ‖ link.seq (8 bytes, big-endian u64)  ‖ link.prev_hash (32)  ‖ 0x1E
//! ```
//!
//! The `0x1F` (ASCII unit separator) delimiters between the variable-length string fields
//! prevent a collision where, e.g., `actor = "ab"`, `scope = "c"` would otherwise hash the same
//! preimage as `actor = "a"`, `scope = "bc"`. The fixed-width fields (`prev_hash`, `seq`,
//! `payload_digest`, each `link.seq`/`link.prev_hash`) are unambiguous by width. The links are
//! hashed in **canonical order** (by [`ChainId`] canonical string, ascending), so the preimage
//! is deterministic regardless of the order they are stored in.
//!
//! Because the one `hash` commits to every link, tampering with **any** event content or **any**
//! link breaks that event's hash — and therefore breaks **every chain the event participates in
//! at that point**, while chains that do not include the event stay intact. That is the native
//! per-scope tamper isolation ([`Ledger::verify_chain`]).
//!
//! The genesis event of the global chain uses `prev_hash = [0u8; 32]`; the seq-0 link of every
//! per-chain lineage uses `prev_hash = [0u8; 32]`.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Field delimiter used between variable-length fields in the hash preimage (ASCII unit sep.).
const FIELD_SEP: u8 = 0x1F;
/// Separator opening, and terminating each entry of, the per-chain links section of the preimage
/// (ASCII record separator).
const RECORD_SEP: u8 = 0x1E;

/// Stable identifier for a ledger event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub uuid::Uuid);

impl EventId {
    /// Mint a fresh random event id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The identity of one hash chain in the native multi-chain model.
///
/// Canonical string forms (used for serialization, storage, and canonical ordering):
///
/// - [`ChainId::Global`] → `"global"` — the primary spine every event shares.
/// - [`ChainId::Application`] → `"application"` — the application-audit chain.
/// - [`ChainId::Tenant`]`(uuid)` → `"tenant:{uuid}"` — a per-tenant chain (wp26 tenancy, spec 05
///   DAT-01). Additive and forward-only: only events whose scope carries a `tenant:{id}` segment
///   join one, so **pre-adoption events are never retro-assigned to a tenant chain** (they are
///   immutable; a re-hash would destroy tamper-evidence). Honest limitation: tenant history begins
///   at adoption, not at instance genesis.
/// - [`ChainId::Company`]`(uuid)` → `"company:{uuid}"` — a per-company book-action chain.
/// - [`ChainId::Book`]`(uuid)` → `"book:{uuid}"` — a per-book book-action chain.
///
/// `Global` is intrinsic and never appears in an event's [`Event::links`]; the others are the
/// non-global chains carried as links.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChainId {
    /// The global chain: the primary spine of every event (`seq`/`prev_hash`/`hash`).
    Global,
    /// The application-audit chain (settings / users / CAE / law / backups).
    Application,
    /// A per-tenant chain (wp26), keyed by the tenant's UUID string. Only events scoped with a
    /// `tenant:{id}` segment join it; existing events never do.
    Tenant(String),
    /// A per-company book-action chain, keyed by the entity's UUID string.
    Company(String),
    /// A per-book book-action chain, keyed by the book's UUID string.
    Book(String),
}

impl ChainId {
    /// The global chain identity.
    pub fn global() -> Self {
        ChainId::Global
    }

    /// Whether this is the intrinsic global chain.
    pub fn is_global(&self) -> bool {
        matches!(self, ChainId::Global)
    }

    /// The canonical string form (`"global"`, `"application"`, `"company:{id}"`, `"book:{id}"`).
    pub fn canonical(&self) -> String {
        self.to_string()
    }

    /// The event kind that a chain's genesis (seq-0) event must carry, if the chain fixes one.
    ///
    /// A `book:` chain's genesis must be `book.opened` (WFL-11: the sealed termo de abertura);
    /// a `company:` chain's genesis must be `entity.created`. The `application` and `global`
    /// chains fix no genesis kind.
    pub fn expected_genesis_kind(&self) -> Option<&'static str> {
        match self {
            ChainId::Book(_) => Some("book.opened"),
            ChainId::Company(_) => Some("entity.created"),
            // A tenant chain fixes no genesis kind: its first event is simply the first tenant-scoped
            // event at adoption (there is no single canonical "tenant created" seal in the chain).
            ChainId::Tenant(_) | ChainId::Global | ChainId::Application => None,
        }
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainId::Global => f.write_str("global"),
            ChainId::Application => f.write_str("application"),
            ChainId::Tenant(id) => write!(f, "tenant:{id}"),
            ChainId::Company(id) => write!(f, "company:{id}"),
            ChainId::Book(id) => write!(f, "book:{id}"),
        }
    }
}

impl Ord for ChainId {
    // Order by the canonical string, ascending — this is the ordering the hash preimage and the
    // link vector are canonicalized against.
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for ChainId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for ChainId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // `collect_str` uses `Display` (the canonical form) without an intermediate allocation.
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Error returned when a string is not a valid [`ChainId`] canonical form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a valid chain id: {0:?}")]
pub struct ChainIdParseError(pub String);

impl FromStr for ChainId {
    type Err = ChainIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "global" => Ok(ChainId::Global),
            "application" => Ok(ChainId::Application),
            other => {
                if let Some(id) = other.strip_prefix("tenant:") {
                    if id.is_empty() {
                        return Err(ChainIdParseError(other.to_owned()));
                    }
                    Ok(ChainId::Tenant(id.to_owned()))
                } else if let Some(id) = other.strip_prefix("company:") {
                    if id.is_empty() {
                        return Err(ChainIdParseError(other.to_owned()));
                    }
                    Ok(ChainId::Company(id.to_owned()))
                } else if let Some(id) = other.strip_prefix("book:") {
                    if id.is_empty() {
                        return Err(ChainIdParseError(other.to_owned()));
                    }
                    Ok(ChainId::Book(id.to_owned()))
                } else {
                    Err(ChainIdParseError(other.to_owned()))
                }
            }
        }
    }
}

/// One event's membership of, and backward link within, a single **non-global** chain.
///
/// The global chain's linkage lives in the event's top-level `seq`/`prev_hash`/`hash`; a
/// `ChainLink` records the same for an `application`/`company`/`book` chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLink {
    /// Which non-global chain this link is for.
    pub chain: ChainId,
    /// This event's position **within that chain** (0 = the chain's genesis).
    pub seq: u64,
    /// Hash of the previous event in that chain, or `[0; 32]` at the chain's genesis.
    pub prev_hash: [u8; 32],
}

/// A single, immutable entry in the ledger's hash chains (DAT-10).
///
/// The fields mirror the audit envelope required by the spec: `actor` (who), `justification`
/// (why, optional), `timestamp` (when), `scope` (which entity/book/act the event concerns),
/// `kind` (a caller-defined event type such as `"act.sealed"`), `payload_digest` (the sha256 of
/// the mutation's content), plus the **global** chaining fields `prev_hash`/`hash` and the
/// per-chain [`links`](Event::links).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Random, stable identity for this event.
    pub id: EventId,
    /// Monotonically increasing position in the **global** chain, starting at 0 for genesis.
    pub seq: u64,
    /// The actor responsible for the mutation (user id, service principal, …).
    pub actor: String,
    /// Optional human justification captured at mutation time.
    pub justification: Option<String>,
    /// When the event was recorded (UTC recommended).
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// The entity/book/act scope this event belongs to (DAT-10); membership derives from it.
    pub scope: String,
    /// Caller-defined event type, e.g. `"book.opened"`, `"act.sealed"`.
    pub kind: String,
    /// sha256 digest of the mutation payload (the content, kept out of the ledger itself).
    pub payload_digest: [u8; 32],
    /// Hash of the preceding event in the **global** chain, or `[0; 32]` for the genesis event.
    pub prev_hash: [u8; 32],
    /// The per-scope (non-global) chains this event joins, **canonically sorted by chain id**.
    pub links: Vec<ChainLink>,
    /// This event's own hash over the single preimage documented at crate level (content +
    /// global link + all per-chain links).
    pub hash: [u8; 32],
}

impl Event {
    /// Recompute this event's hash from its own fields (including [`links`](Event::links)) and a
    /// supplied global `prev_hash`.
    ///
    /// Used both when appending (to fill in `hash`) and when verifying (to detect any tampering
    /// with the stored fields, the global linkage, or any per-chain link).
    fn compute_hash(&self, prev_hash: &[u8; 32]) -> [u8; 32] {
        compute_hash(
            prev_hash,
            self.seq,
            &self.actor,
            &self.scope,
            &self.kind,
            self.timestamp,
            &self.payload_digest,
            &self.links,
        )
    }
}

/// Errors surfaced when a chain fails verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// The genesis event did not carry the required all-zero global `prev_hash`.
    #[error("genesis event (seq 0) must have an all-zero prev_hash")]
    BadGenesis,
    /// Global sequence numbers were not the expected strictly-increasing 0,1,2,… run.
    #[error("sequence broken at index {index}: expected seq {expected}, found {found}")]
    SequenceBroken {
        /// Position in the event vector where the break was detected.
        index: usize,
        /// The `seq` value the global chain required at this position.
        expected: u64,
        /// The `seq` value actually found.
        found: u64,
    },
    /// An event's stored global `prev_hash` did not match the previous event's `hash`.
    #[error("chain link broken at seq {seq}: prev_hash does not match preceding event")]
    LinkBroken {
        /// The `seq` of the event whose global backward link is broken.
        seq: u64,
    },
    /// An event's stored `hash` did not match a recomputation of its own contents (including
    /// links) — the event was altered after sealing.
    #[error("event hash mismatch at seq {seq}: contents were altered after sealing")]
    HashMismatch {
        /// The global `seq` of the tampered event.
        seq: u64,
    },
    /// A per-chain sequence run (within one non-global chain) was not the expected 0,1,2,….
    #[error("chain {chain} sequence broken: expected chain-seq {expected}, found {found}")]
    ChainSequenceBroken {
        /// The chain whose per-chain sequence is broken.
        chain: ChainId,
        /// The chain-seq value the chain required at this position.
        expected: u64,
        /// The chain-seq value actually found.
        found: u64,
    },
    /// A per-chain backward link (within one non-global chain) did not match the previous
    /// member's `hash`.
    #[error(
        "chain {chain} link broken at chain-seq {seq}: prev_hash does not match preceding member"
    )]
    ChainLinkBroken {
        /// The chain whose backward link is broken.
        chain: ChainId,
        /// The chain-seq of the member whose backward link is broken.
        seq: u64,
    },
    /// A chain's genesis (seq-0) member did not carry the event kind that chain requires
    /// (WFL-11: `book.opened` for a `book:` chain, `entity.created` for a `company:` chain).
    #[error("chain {chain} genesis kind wrong: expected {expected:?}, found {found:?}")]
    ChainGenesisWrong {
        /// The chain whose genesis kind is wrong.
        chain: ChainId,
        /// The event kind the chain's genesis must carry.
        expected: String,
        /// The event kind actually found at the chain's genesis.
        found: String,
    },
}

/// A verification-time status snapshot for one chain (powers the API `chains` surface and web).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStatus {
    /// Which chain this status describes.
    pub chain: ChainId,
    /// The kind of the chain's genesis (seq-0) member, if the chain has any members.
    pub genesis_kind: Option<String>,
    /// Number of events belonging to this chain.
    pub length: u64,
    /// The hash of the chain's most recent member (its head), or `None` when empty.
    pub head: Option<[u8; 32]>,
    /// Whether the chain re-verifies cleanly ([`Ledger::verify_chain`]).
    pub verified: bool,
    /// The precise first break in this chain, or `None` when it verifies cleanly (additive t54).
    ///
    /// This is the rich counterpart of `verified`: when `verified` is `false`, `first_break`
    /// pinpoints the chain/seq/event-id/expected-vs-actual hash of the failure. Defaulted for
    /// serde so previously-persisted [`ChainStatus`] JSON (which predates this field) still loads.
    #[serde(default)]
    pub first_break: Option<ChainBreak>,
}

/// Compute the sha256 digest of an arbitrary payload (the DAT-10 payload digest).
///
/// Callers digest their mutation content here and pass the result into the ledger, so the ledger
/// records *what changed* without storing the (possibly large or sensitive) content.
pub fn digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().into()
}

/// Compute an event hash from its constituent fields. See the crate-level preimage docs.
///
/// The `links` are hashed in **canonical order** (by chain id ascending), so the preimage is
/// deterministic regardless of the order they are supplied in.
#[allow(clippy::too_many_arguments)]
fn compute_hash(
    prev_hash: &[u8; 32],
    seq: u64,
    actor: &str,
    scope: &str,
    kind: &str,
    timestamp: OffsetDateTime,
    payload_digest: &[u8; 32],
    links: &[ChainLink],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(seq.to_be_bytes());
    hasher.update(actor.as_bytes());
    hasher.update([FIELD_SEP]);
    hasher.update(scope.as_bytes());
    hasher.update([FIELD_SEP]);
    hasher.update(kind.as_bytes());
    hasher.update([FIELD_SEP]);
    // RFC 3339 is a stable, unambiguous, round-trippable textual encoding of the instant.
    let ts = timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    hasher.update(ts.as_bytes());
    hasher.update([FIELD_SEP]);
    hasher.update(payload_digest);
    // Links section: a single record separator, then each link (in canonical chain-id order)
    // as `chain_id 0x1F seq(8 BE) prev_hash(32) 0x1E`.
    hasher.update([RECORD_SEP]);
    let mut ordered: Vec<&ChainLink> = links.iter().collect();
    ordered.sort_by(|a, b| a.chain.cmp(&b.chain));
    for link in ordered {
        hasher.update(link.chain.to_string().as_bytes());
        hasher.update([FIELD_SEP]);
        hasher.update(link.seq.to_be_bytes());
        hasher.update(link.prev_hash);
        hasher.update([RECORD_SEP]);
    }
    hasher.finalize().into()
}

/// An append-only, natively multi-chain, hash-chained ledger of events (DAT-10/11).
///
/// The ledger is write-once from the outside: there is no public API to mutate or remove an
/// existing event. New events may only be appended; each append links to the prior event's hash
/// on the global chain and on every non-global chain it joins. [`Ledger::verify`] recomputes
/// every chain to detect any tampering; [`Ledger::verify_chain`] isolates one chain.
///
/// The only serialized state is `events`; all per-chain heads/lengths are derived from the log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ledger {
    events: Vec<Event>,
}

impl Ledger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstruct a ledger from previously-persisted events, adopting their stored hashes.
    ///
    /// This is the boot-time counterpart to [`Ledger::append`]: where `append` mints fresh
    /// events (capturing a new timestamp and computing a new hash), `try_from_events` **adopts
    /// the events exactly as persisted** — it does *not* re-append or re-hash them, so the frozen
    /// hash preimage and every stored `hash`/`prev_hash`/`links`/`timestamp` are preserved
    /// byte-for-byte. A store backend replays its rows (ordered by `seq`, links reattached)
    /// through here to rebuild the in-memory chains after a restart.
    ///
    /// The adopted chains are then run through the **same** verification as [`Ledger::verify`],
    /// so a tampered or truncated store is detected. Rather than refusing to construct, this
    /// returns the (always-constructed) [`Ledger`] alongside the verification outcome: `Ok(n)`
    /// for sound chains totalling `n` events, or the first [`LedgerError`] for a broken one.
    /// Callers (the boot path) surface a broken chain loudly but can still start and inspect it.
    ///
    /// An empty input yields an empty ledger and `Ok(0)`.
    pub fn try_from_events(events: Vec<Event>) -> (Ledger, Result<u64, LedgerError>) {
        let ledger = Ledger { events };
        let status = ledger.verify();
        (ledger, status)
    }

    /// Derive the chain membership (the non-global chains) of an event with this `scope`/`kind`.
    ///
    /// The frozen scope grammar (contract §3.2):
    ///
    /// - `entity:{eid}/book:{bid}[/act:{aid}]` → `[Book(bid), Company(eid)]`;
    /// - `book:{bid}/act:{aid}` (the entity-less act fallback) → `[Book(bid)]`;
    /// - a bare UUID → `[Company(uuid)]`;
    /// - any other keyword scope (`settings`, `cae`, `law`, `user`, `backup`, …) → `[Application]`.
    ///
    /// The result is **canonically sorted** by chain id. Membership derives from `scope`; `kind`
    /// is part of the frozen grammar signature but is not currently needed to disambiguate (an
    /// app keyword is never a UUID, and the hierarchy is fully encoded in the scope).
    pub fn memberships(scope: &str, _kind: &str) -> Vec<ChainId> {
        // Filter out empty segment values (SCOPE-01): an `entity:` or `book:` prefix with no ID
        // after it must not create a chain with an empty id (which would be a spurious chain and
        // could confuse chain verification). An empty entity/book id is treated as absent.
        let tenant_id = segment_value(scope, "tenant:").filter(|s| !s.is_empty());
        let entity_id = segment_value(scope, "entity:").filter(|s| !s.is_empty());
        let book_id = segment_value(scope, "book:").filter(|s| !s.is_empty());
        let mut chains = Vec::new();
        // wp26: a `tenant:{tid}` segment adds the per-tenant chain, additively, alongside whatever
        // company/book chains the rest of the scope implies. Only events whose scope carries this
        // segment join a tenant chain — existing (pre-adoption) events never do.
        if let Some(tid) = tenant_id {
            chains.push(ChainId::Tenant(tid.to_owned()));
        }
        if let Some(eid) = entity_id {
            chains.push(ChainId::Company(eid.to_owned()));
            if let Some(bid) = book_id {
                chains.push(ChainId::Book(bid.to_owned()));
            }
        } else if let Some(bid) = book_id {
            // Entity-less `book:{bid}/act:{aid}` fallback: the book chain only (company unknown).
            chains.push(ChainId::Book(bid.to_owned()));
        } else if tenant_id.is_none() && uuid::Uuid::parse_str(scope).is_ok() {
            chains.push(ChainId::Company(scope.to_owned()));
        } else if chains.is_empty() {
            chains.push(ChainId::Application);
        }
        chains.sort();
        chains
    }

    /// Append a new event and return a reference to it.
    ///
    /// The new event's global `seq` is the current length and its global `prev_hash` is the
    /// previous event's `hash` (or `[0; 32]` for genesis). Its per-chain [`links`](Event::links)
    /// are derived from `scope`/`kind` via [`Ledger::memberships`], each linked to that chain's
    /// current head. Its `timestamp` is captured as `now` in UTC, and its single `hash` is
    /// computed over the preimage documented at crate level.
    ///
    /// The signature is intentionally unchanged from the single-chain era: membership and
    /// linkage are derived internally, so callers append exactly as before.
    pub fn append(
        &mut self,
        actor: &str,
        scope: &str,
        kind: &str,
        justification: Option<&str>,
        payload: &[u8],
    ) -> &Event {
        // Behaviour is byte-identical to the original single-argument era: capture `now` here and
        // delegate to the timestamp-supplied core. The frozen preimage and every produced hash are
        // unchanged — this is a pure internal refactor so clock-free callers (`reanchor`) can reuse
        // the same append core with a caller-supplied instant.
        let timestamp = OffsetDateTime::now_utc();
        self.append_at(actor, scope, kind, justification, payload, timestamp)
    }

    /// The append core, parameterised on the event `timestamp` (see [`Ledger::append`]).
    ///
    /// [`Ledger::append`] passes `OffsetDateTime::now_utc()`; clock-free internal callers pass a
    /// caller-supplied instant. The resulting event, hash preimage, per-chain links, and every
    /// stored field are identical to what `append` produced before this refactor existed.
    fn append_at(
        &mut self,
        actor: &str,
        scope: &str,
        kind: &str,
        justification: Option<&str>,
        payload: &[u8],
        timestamp: OffsetDateTime,
    ) -> &Event {
        let seq = self.events.len() as u64;
        let prev_hash = self.events.last().map(|e| e.hash).unwrap_or([0u8; 32]);
        let payload_digest = digest(payload);

        // Per-chain heads, derived from the log, give each new link its seq + backward hash.
        let heads = self.chain_heads();
        let mut links: Vec<ChainLink> = Ledger::memberships(scope, kind)
            .into_iter()
            .map(|chain| {
                let (link_seq, link_prev) = match heads.get(&chain) {
                    Some(&(head_seq, head_hash)) => (head_seq + 1, head_hash),
                    None => (0, [0u8; 32]),
                };
                ChainLink {
                    chain,
                    seq: link_seq,
                    prev_hash: link_prev,
                }
            })
            .collect();
        links.sort_by(|a, b| a.chain.cmp(&b.chain));

        let hash = compute_hash(
            &prev_hash,
            seq,
            actor,
            scope,
            kind,
            timestamp,
            &payload_digest,
            &links,
        );
        self.events.push(Event {
            id: EventId::new(),
            seq,
            actor: actor.to_owned(),
            justification: justification.map(str::to_owned),
            timestamp,
            scope: scope.to_owned(),
            kind: kind.to_owned(),
            payload_digest,
            prev_hash,
            links,
            hash,
        });
        self.events.last().expect("just pushed an event")
    }

    /// The current head `(chain-seq, hash)` of every **non-global** chain, derived from the log.
    ///
    /// Because events are stored in global order, iterating and overwriting yields, for each
    /// chain, the most recent member's link-seq paired with that member's event hash.
    fn chain_heads(&self) -> HashMap<ChainId, (u64, [u8; 32])> {
        let mut heads: HashMap<ChainId, (u64, [u8; 32])> = HashMap::new();
        for event in &self.events {
            for link in &event.links {
                heads.insert(link.chain.clone(), (link.seq, event.hash));
            }
        }
        heads
    }

    /// Verify **every** chain: the global spine, each per-scope chain, and the genesis-kind
    /// invariants — in one uniform pass.
    ///
    /// On success returns the number of events. On failure returns the first broken link. The
    /// global spine is checked first (per event): `seq` run, genesis `prev_hash`, backward
    /// linkage, and `hash` recomputation (which covers content **and** every link). Then each of
    /// the event's per-chain links is checked: the per-chain `seq` run, the per-chain backward
    /// linkage, and — at a chain's genesis — its required event kind (WFL-11).
    ///
    /// An empty ledger verifies successfully (returns `Ok(0)`).
    pub fn verify(&self) -> Result<u64, LedgerError> {
        let mut global_prev = [0u8; 32];
        // Per non-global chain: the last member's (chain-seq, event hash) seen so far.
        let mut chain_state: HashMap<ChainId, (u64, [u8; 32])> = HashMap::new();
        for (index, event) in self.events.iter().enumerate() {
            // --- Global spine ---
            let expected_seq = index as u64;
            if event.seq != expected_seq {
                return Err(LedgerError::SequenceBroken {
                    index,
                    expected: expected_seq,
                    found: event.seq,
                });
            }
            if index == 0 && event.prev_hash != [0u8; 32] {
                return Err(LedgerError::BadGenesis);
            }
            if event.prev_hash != global_prev {
                return Err(LedgerError::LinkBroken { seq: event.seq });
            }
            if event.compute_hash(&event.prev_hash) != event.hash {
                return Err(LedgerError::HashMismatch { seq: event.seq });
            }

            // --- Per-scope chains (links are canonically ordered) ---
            for link in &event.links {
                match chain_state.get(&link.chain) {
                    None => check_chain_genesis(&link.chain, link, &event.kind)?,
                    Some(&(last_seq, last_hash)) => {
                        let expected = last_seq + 1;
                        if link.seq != expected {
                            return Err(LedgerError::ChainSequenceBroken {
                                chain: link.chain.clone(),
                                expected,
                                found: link.seq,
                            });
                        }
                        if link.prev_hash != last_hash {
                            return Err(LedgerError::ChainLinkBroken {
                                chain: link.chain.clone(),
                                seq: link.seq,
                            });
                        }
                    }
                }
                chain_state.insert(link.chain.clone(), (link.seq, event.hash));
            }

            global_prev = event.hash;
        }
        Ok(self.events.len() as u64)
    }

    /// Verify a single chain in isolation, re-walking only its members (powers `?chain=`).
    ///
    /// For every member the event's `hash` is recomputed (catching any content or link
    /// tampering), then the chain's own `seq` run, genesis kind, and backward linkage are
    /// checked. Because each event's hash commits to all its links, tampering with an event that
    /// belongs to this chain breaks *this* chain, while chains that do not include that event
    /// verify cleanly — the native per-scope tamper isolation.
    ///
    /// [`ChainId::Global`] re-walks the whole global spine. Returns the chain's length on
    /// success; a chain with no members returns `Ok(0)`.
    pub fn verify_chain(&self, chain: &ChainId) -> Result<u64, LedgerError> {
        if chain.is_global() {
            return self.verify_global();
        }
        let mut state: Option<(u64, [u8; 32])> = None;
        let mut count = 0u64;
        for event in &self.events {
            let Some(link) = event.links.iter().find(|l| &l.chain == chain) else {
                continue;
            };
            if event.compute_hash(&event.prev_hash) != event.hash {
                return Err(LedgerError::HashMismatch { seq: event.seq });
            }
            match state {
                None => check_chain_genesis(chain, link, &event.kind)?,
                Some((last_seq, last_hash)) => {
                    let expected = last_seq + 1;
                    if link.seq != expected {
                        return Err(LedgerError::ChainSequenceBroken {
                            chain: chain.clone(),
                            expected,
                            found: link.seq,
                        });
                    }
                    if link.prev_hash != last_hash {
                        return Err(LedgerError::ChainLinkBroken {
                            chain: chain.clone(),
                            seq: link.seq,
                        });
                    }
                }
            }
            state = Some((link.seq, event.hash));
            count += 1;
        }
        Ok(count)
    }

    /// Verify only the global spine (used by [`Ledger::verify_chain`] for [`ChainId::Global`]).
    fn verify_global(&self) -> Result<u64, LedgerError> {
        let mut global_prev = [0u8; 32];
        for (index, event) in self.events.iter().enumerate() {
            let expected_seq = index as u64;
            if event.seq != expected_seq {
                return Err(LedgerError::SequenceBroken {
                    index,
                    expected: expected_seq,
                    found: event.seq,
                });
            }
            if index == 0 && event.prev_hash != [0u8; 32] {
                return Err(LedgerError::BadGenesis);
            }
            if event.prev_hash != global_prev {
                return Err(LedgerError::LinkBroken { seq: event.seq });
            }
            if event.compute_hash(&event.prev_hash) != event.hash {
                return Err(LedgerError::HashMismatch { seq: event.seq });
            }
            global_prev = event.hash;
        }
        Ok(self.events.len() as u64)
    }

    /// A [`ChainStatus`] for a single chain, or `None` if a non-global chain has no members.
    ///
    /// [`ChainId::Global`] always yields a status (empty ledger → length 0, head `None`).
    pub fn chain_status(&self, chain: &ChainId) -> Option<ChainStatus> {
        if chain.is_global() {
            let first_break = self.locate_break(chain);
            return Some(ChainStatus {
                chain: chain.clone(),
                genesis_kind: self.events.first().map(|e| e.kind.clone()),
                length: self.events.len() as u64,
                head: self.head(),
                verified: first_break.is_none(),
                first_break,
            });
        }
        let members: Vec<&Event> = self.events_in_chain(chain);
        if members.is_empty() {
            return None;
        }
        let first_break = self.locate_break(chain);
        Some(ChainStatus {
            chain: chain.clone(),
            genesis_kind: members.first().map(|e| e.kind.clone()),
            length: members.len() as u64,
            head: members.last().map(|e| e.hash),
            verified: first_break.is_none(),
            first_break,
        })
    }

    /// A [`ChainStatus`] for every **non-global** chain (application + each company + each book),
    /// canonically sorted by chain id. The global chain is reported separately via
    /// [`Ledger::chain_status`]`(&ChainId::Global)`.
    pub fn chains(&self) -> Vec<ChainStatus> {
        self.distinct_non_global_chains()
            .into_iter()
            .filter_map(|c| self.chain_status(&c))
            .collect()
    }

    /// The distinct non-global chains present in the log, canonically sorted.
    fn distinct_non_global_chains(&self) -> Vec<ChainId> {
        let mut set: BTreeSet<ChainId> = BTreeSet::new();
        for event in &self.events {
            for link in &event.links {
                set.insert(link.chain.clone());
            }
        }
        set.into_iter().collect()
    }

    /// The events belonging to `chain`, in global order. For [`ChainId::Global`] this is every
    /// event; for a non-global chain, its members.
    pub fn events_in_chain(&self, chain: &ChainId) -> Vec<&Event> {
        if chain.is_global() {
            return self.events.iter().collect();
        }
        self.events
            .iter()
            .filter(|e| e.links.iter().any(|l| &l.chain == chain))
            .collect()
    }

    /// The number of events belonging to `chain` (its length).
    pub fn chain_length(&self, chain: &ChainId) -> u64 {
        if chain.is_global() {
            return self.events.len() as u64;
        }
        self.events
            .iter()
            .filter(|e| e.links.iter().any(|l| &l.chain == chain))
            .count() as u64
    }

    /// The hash of `chain`'s most recent member (its head), or `None` when the chain is empty.
    pub fn chain_head(&self, chain: &ChainId) -> Option<[u8; 32]> {
        if chain.is_global() {
            return self.head();
        }
        self.events
            .iter()
            .rev()
            .find(|e| e.links.iter().any(|l| &l.chain == chain))
            .map(|e| e.hash)
    }

    /// Borrow the full event log in append (global) order.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// The hash of the most recent event, i.e. the current global chain head (`None` if empty).
    pub fn head(&self) -> Option<[u8; 32]> {
        self.events.last().map(|e| e.hash)
    }

    /// Number of events in the ledger.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the ledger has no events yet.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// The value of the first `/`-separated segment of `scope` that begins with `prefix`.
///
/// E.g. `segment_value("entity:E/book:B/act:A", "book:") == Some("B")`.
fn segment_value<'a>(scope: &'a str, prefix: &str) -> Option<&'a str> {
    scope.split('/').find_map(|seg| seg.strip_prefix(prefix))
}

/// Check a chain's genesis (seq-0) member: its link must be seq 0 with an all-zero backward link,
/// and its event kind must match the chain's required genesis kind (if any).
fn check_chain_genesis(
    chain: &ChainId,
    link: &ChainLink,
    event_kind: &str,
) -> Result<(), LedgerError> {
    if link.seq != 0 {
        return Err(LedgerError::ChainSequenceBroken {
            chain: chain.clone(),
            expected: 0,
            found: link.seq,
        });
    }
    if link.prev_hash != [0u8; 32] {
        return Err(LedgerError::ChainLinkBroken {
            chain: chain.clone(),
            seq: link.seq,
        });
    }
    if let Some(expected) = chain.expected_genesis_kind()
        && event_kind != expected
    {
        return Err(LedgerError::ChainGenesisWrong {
            chain: chain.clone(),
            expected: expected.to_owned(),
            found: event_kind.to_owned(),
        });
    }
    Ok(())
}

// =============================================================================================
// t54 — chain integrity RECOVERY + ENFORCEMENT + per-book portability (ADDITIVE).
//
// Everything below is strictly additive. The frozen hash preimage (`compute_hash`), the
// `verify()`/`verify_chain()` contracts, `LedgerError`, `Event`'s fields + serialization, the
// genesis rules, and `try_from_events` are all UNCHANGED — these are new types + new methods that
// layer richer break-location, a validating append, an audited re-anchor, and a standalone bundle
// verifier on top of the existing tamper-evident core.
// =============================================================================================

/// The classification of a chain break — the rich, machine-readable counterpart of the
/// [`LedgerError`] variants (which stay the byte-frozen `verify()` contract).
///
/// Each variant corresponds 1:1 to a way [`Ledger::verify`]/[`Ledger::verify_chain`] can fail, so
/// a [`ChainBreak`] is always derivable from the same walk without changing the old error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakKind {
    /// The global genesis event (seq 0) did not carry an all-zero `prev_hash`.
    BadGenesis,
    /// The global `seq` run was not the expected strictly-increasing 0,1,2,….
    SequenceBroken,
    /// An event's global `prev_hash` did not match the previous event's `hash`.
    LinkBroken,
    /// An event's stored `hash` did not match a recomputation of its own contents.
    HashMismatch,
    /// A per-chain `seq` run (within one non-global chain) was not the expected 0,1,2,….
    ChainSequenceBroken,
    /// A per-chain backward link did not match the previous member's `hash`.
    ChainLinkBroken,
    /// A chain's genesis member did not carry that chain's required event kind (WFL-11).
    ChainGenesisWrong,
}

/// The precise first break located in a chain: which chain, what kind, where (global + chain seq,
/// event id), and — for a link/hash failure — the expected-vs-actual 32-byte hashes.
///
/// This is a snapshot, never persisted into the frozen event log; it is the single detail type the
/// api/store/web surfaces surface (via [`Ledger::locate_break`] / [`Ledger::integrity_report`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainBreak {
    /// The chain the break was found in.
    pub chain: ChainId,
    /// The classification of the break.
    pub kind: BreakKind,
    /// The global `seq` of the offending event, when a specific event is implicated.
    pub global_seq: Option<u64>,
    /// The per-chain seq of the offending link, for a per-chain (non-global) break.
    pub chain_seq: Option<u64>,
    /// The id of the offending event, when a specific event is implicated.
    pub event_id: Option<EventId>,
    /// The hash the chain required at this point (the previous member's hash, or the recomputed
    /// self-hash), for a link/hash break.
    pub expected_hash: Option<[u8; 32]>,
    /// The hash actually found (the stored `prev_hash`, or the stored `hash`), for a link/hash
    /// break.
    pub actual_hash: Option<[u8; 32]>,
    /// A human-readable description (mirrors the corresponding [`LedgerError`] `Display`).
    pub message: String,
}

/// A whole-ledger integrity snapshot: the global spine's status, every non-global chain's status
/// (each carrying its own [`ChainBreak`] when broken), an overall `healthy` flag, and the
/// permanent re-anchor disclosure derived from the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// The global spine's status (always present, even for an empty ledger).
    pub global: ChainStatus,
    /// One status per non-global chain, canonically ordered by chain id.
    pub chains: Vec<ChainStatus>,
    /// `true` iff the global spine and every non-global chain verify cleanly.
    pub healthy: bool,
    /// The re-anchor records disclosed by the audit chain (permanent; empty when none).
    pub reanchored_segments: Vec<ReanchorRecord>,
}

/// Why a [`Ledger::try_append`] was rejected before mutating the ledger.
///
/// A rejection means nothing was appended: the caller can safely retry, roll back a surrounding
/// transaction, or surface the break — the ledger is untouched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppendError {
    /// The new event would be a chain's genesis, but its `kind` is not that chain's required
    /// genesis kind (WFL-11: `book.opened` for a `book:` chain, `entity.created` for `company:`).
    #[error("chain {chain} genesis kind wrong: expected {expected:?}, found {found:?}")]
    ChainGenesisWrong {
        /// The chain whose genesis kind would be wrong.
        chain: ChainId,
        /// The kind the chain's genesis must carry.
        expected: String,
        /// The kind actually supplied.
        found: String,
    },
    /// A chain the new event would join already has a broken tail (its head event no longer
    /// self-verifies), so appending onto it would perpetuate a break. The ledger is not mutated.
    #[error("chain {chain} tail is broken; refusing to append onto a broken chain")]
    BrokenChainTail {
        /// The chain whose current tail is broken.
        chain: ChainId,
        /// The break detected at the tail.
        break_: ChainBreak,
    },
}

/// A record of one re-anchor operation, disclosed permanently via a chained `ledger.reanchored`
/// audit event (never a forgeable out-of-preimage flag). See [`Ledger::reanchor`].
///
/// The record is committed into the tamper-evident chain: its canonical JSON is the payload the
/// `ledger.reanchored` event digests (`payload_digest`), and the same JSON is retained in the
/// event's `justification` so [`Ledger::reanchored_segments`] can reconstruct it. Tampering with
/// the retained JSON is detectable (its digest would no longer match `payload_digest`, which is in
/// the frozen hash preimage), so the disclosure cannot be silently altered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReanchorRecord {
    /// Who performed the re-anchor.
    pub actor: String,
    /// When it was performed (caller-supplied; the core takes no clock).
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// The required, non-empty human reason for the last-resort operation.
    pub reason: String,
    /// The chains (and their chain-seq ranges) whose hashes were rebuilt.
    pub affected: Vec<ReanchorSegment>,
    /// The global head hash before the rebuild (the broken head), or `None` for an empty ledger.
    pub original_global_head: Option<[u8; 32]>,
    /// The global head hash after the rebuild (before the audit event was appended).
    pub new_global_head: [u8; 32],
    /// sha256 over the concatenation of every event's overwritten `hash` (in global order),
    /// preserving what the rebuild replaced so the original (broken) state stays provable.
    pub pre_reanchor_digest: [u8; 32],
}

/// One chain's rebuilt range within a [`ReanchorRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReanchorSegment {
    /// The affected chain.
    pub chain: ChainId,
    /// The lowest chain-seq whose hash changed in the rebuild.
    pub from_chain_seq: u64,
    /// The highest chain-seq whose hash changed in the rebuild.
    pub to_chain_seq: u64,
}

/// Why a [`Ledger::reanchor`] was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReanchorError {
    /// The ledger already verifies cleanly — a re-anchor would needlessly rewrite sound hashes.
    #[error("ledger already verifies; re-anchor refused (nothing to repair)")]
    AlreadyValid,
    /// The required human reason was empty or whitespace-only.
    #[error("re-anchor requires a non-empty reason")]
    EmptyReason,
    /// The rebuild did not produce a cleanly-verifying ledger (should never happen; defensive).
    #[error("re-anchor failed to produce a verifying ledger: {0}")]
    VerificationFailed(LedgerError),
}

/// The verdict of the standalone bundle-chain verifier ([`Ledger::verify_bundle_chain_verdict`]).
///
/// This is the ergonomic enum form of the frozen [`Ledger::verify_bundle_chain`] primitive
/// (`Result<u64, ChainBreak>`), for callers that prefer a match over a `Result`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleVerdict {
    /// The isolated chain verified end-to-end; carries its length.
    Verified {
        /// The number of members verified in the isolated chain.
        length: u64,
    },
    /// The isolated chain is broken; carries the precise first break.
    Broken(ChainBreak),
}

/// The kind stamped on the chained audit event a [`Ledger::reanchor`] appends.
pub const REANCHOR_EVENT_KIND: &str = "ledger.reanchored";
/// The scope stamped on the chained audit event a [`Ledger::reanchor`] appends (⇒ Application).
pub const RECOVERY_SCOPE: &str = "recovery";

/// The kind stamped on the append-only GDPR **right-to-erasure attestation** event (wp26-gdpr).
///
/// Destructive erasure of a data subject's personal data (physical row/blob deletion + destruction
/// of the subject's per-subject DEK, making at-rest ciphertext — including backups — irrecoverable)
/// **never mutates any existing `events` row**: the ledger stores only `payload_digest` and
/// pseudonymous references, so deleting the store-side PII cannot break [`Ledger::verify`]. The
/// erasure is instead proven by appending exactly one event of this kind, whose digested payload
/// records the subject id, the authorizing DSR request, the dual-control principals, the techniques
/// applied, the erased target counts, and the lawfully-retained Art. 17(3) carve-outs. Because it is
/// a normal append, `verify()` goes from `Ok(n)` to `Ok(n + 1)` and tamper-evidence is preserved.
///
/// Stamp this event's `scope` with a keyword scope (e.g. `user:{uuid}`) so [`Ledger::memberships`]
/// routes it to the [`ChainId::Application`] chain, which fixes no genesis kind (a bare-UUID or
/// `book:`/`entity:` scope is avoided to sidestep the WFL-11 genesis-kind constraint).
pub const SUBJECT_ERASED_KIND: &str = "subject.erased";

/// The kind stamped on an append-only **rectification annotation** event (wp26-gdpr).
///
/// GDPR Art. 17(3)(b): PII embedded in sealed company acts (livro de atas), books, and signed legal
/// documents carries a **statutory retention** obligation and cannot be erased — and rewriting it
/// would break the signatures over it. The standard data-subject remedy is therefore **annotation**,
/// not deletion: a correction is recorded as a NEW append-only event linked to the record, leaving the
/// sealed/signed payload byte-identical (so its signatures stay valid). This is the norm; destructive
/// erasure is the narrow exception for genuinely non-legally-required PII.
pub const SUBJECT_RECTIFICATION_KIND: &str = "subject.rectification_noted";

/// The kind stamped on an append-only **restriction-of-processing / objection** marker event
/// (wp26-gdpr; GDPR Art. 18/21). Like [`SUBJECT_RECTIFICATION_KIND`], it is a new append-only event
/// recorded against the record and never mutates any sealed/signed payload, so signatures stay valid.
pub const SUBJECT_PROCESSING_RESTRICTED_KIND: &str = "subject.processing_restricted";

/// Pseudonymous-actor convention for post-erasure accountability (wp26-gdpr).
///
/// New event stamping SHOULD record `actor` as the subject **UUID**, not a human-readable username
/// slug: once a subject is erased the `users` row mapping uuid→identity is gone, so a stored UUID
/// actor becomes a dangling pseudonym rather than attributable PII. Historic events keep their
/// already-stored `actor` bytes immutably (they are never rewritten); where those still expose a
/// username or other identifier, the retention of that accountability field is the lawful Art. 17(3)
/// carve-out surfaced by the erasure preflight — never an in-place edit of the frozen ledger.
pub const SUBJECT_ERASED_ACTOR_IS_UUID_NOTE: &str =
    "wp26-gdpr: stamp actor = subject UUID, not username slug";

impl Ledger {
    // ---- §2.1 break location -----------------------------------------------------------------

    /// Locate the precise first break in `chain`, or `None` when it verifies cleanly.
    ///
    /// This walks exactly the same checks as [`Ledger::verify`] (for [`ChainId::Global`]) or
    /// [`Ledger::verify_chain`] (for a non-global chain) — so `locate_break(c).is_none()` is
    /// equivalent to `verify_chain(c).is_ok()` — but returns the rich [`ChainBreak`] (event id,
    /// global + chain seq, expected-vs-actual hash bytes) instead of a bool/[`LedgerError`].
    pub fn locate_break(&self, chain: &ChainId) -> Option<ChainBreak> {
        if chain.is_global() {
            return self.locate_global_break();
        }
        let mut state: Option<(u64, [u8; 32])> = None;
        for event in &self.events {
            let Some(link) = event.links.iter().find(|l| &l.chain == chain) else {
                continue;
            };
            let recomputed = event.compute_hash(&event.prev_hash);
            if recomputed != event.hash {
                return Some(ChainBreak {
                    chain: chain.clone(),
                    kind: BreakKind::HashMismatch,
                    global_seq: Some(event.seq),
                    chain_seq: Some(link.seq),
                    event_id: Some(event.id),
                    expected_hash: Some(recomputed),
                    actual_hash: Some(event.hash),
                    message: format!(
                        "event hash mismatch at seq {}: contents were altered after sealing",
                        event.seq
                    ),
                });
            }
            match state {
                None => {
                    if let Some(b) = genesis_break(chain, event, link) {
                        return Some(b);
                    }
                }
                Some((last_seq, last_hash)) => {
                    let expected = last_seq + 1;
                    if link.seq != expected {
                        return Some(ChainBreak {
                            chain: chain.clone(),
                            kind: BreakKind::ChainSequenceBroken,
                            global_seq: Some(event.seq),
                            chain_seq: Some(link.seq),
                            event_id: Some(event.id),
                            expected_hash: None,
                            actual_hash: None,
                            message: format!(
                                "chain {chain} sequence broken: expected chain-seq {expected}, \
                                 found {}",
                                link.seq
                            ),
                        });
                    }
                    if link.prev_hash != last_hash {
                        return Some(ChainBreak {
                            chain: chain.clone(),
                            kind: BreakKind::ChainLinkBroken,
                            global_seq: Some(event.seq),
                            chain_seq: Some(link.seq),
                            event_id: Some(event.id),
                            expected_hash: Some(last_hash),
                            actual_hash: Some(link.prev_hash),
                            message: format!(
                                "chain {chain} link broken at chain-seq {}: prev_hash does not \
                                 match preceding member",
                                link.seq
                            ),
                        });
                    }
                }
            }
            state = Some((link.seq, event.hash));
        }
        None
    }

    /// Locate the first break on the global spine, or `None` when it verifies cleanly.
    fn locate_global_break(&self) -> Option<ChainBreak> {
        let mut global_prev = [0u8; 32];
        for (index, event) in self.events.iter().enumerate() {
            let expected_seq = index as u64;
            if event.seq != expected_seq {
                return Some(ChainBreak {
                    chain: ChainId::Global,
                    kind: BreakKind::SequenceBroken,
                    global_seq: Some(event.seq),
                    chain_seq: None,
                    event_id: Some(event.id),
                    expected_hash: None,
                    actual_hash: None,
                    message: format!(
                        "sequence broken at index {index}: expected seq {expected_seq}, found {}",
                        event.seq
                    ),
                });
            }
            if index == 0 && event.prev_hash != [0u8; 32] {
                return Some(ChainBreak {
                    chain: ChainId::Global,
                    kind: BreakKind::BadGenesis,
                    global_seq: Some(event.seq),
                    chain_seq: None,
                    event_id: Some(event.id),
                    expected_hash: Some([0u8; 32]),
                    actual_hash: Some(event.prev_hash),
                    message: "genesis event (seq 0) must have an all-zero prev_hash".to_owned(),
                });
            }
            if event.prev_hash != global_prev {
                return Some(ChainBreak {
                    chain: ChainId::Global,
                    kind: BreakKind::LinkBroken,
                    global_seq: Some(event.seq),
                    chain_seq: None,
                    event_id: Some(event.id),
                    expected_hash: Some(global_prev),
                    actual_hash: Some(event.prev_hash),
                    message: format!(
                        "chain link broken at seq {}: prev_hash does not match preceding event",
                        event.seq
                    ),
                });
            }
            let recomputed = event.compute_hash(&event.prev_hash);
            if recomputed != event.hash {
                return Some(ChainBreak {
                    chain: ChainId::Global,
                    kind: BreakKind::HashMismatch,
                    global_seq: Some(event.seq),
                    chain_seq: None,
                    event_id: Some(event.id),
                    expected_hash: Some(recomputed),
                    actual_hash: Some(event.hash),
                    message: format!(
                        "event hash mismatch at seq {}: contents were altered after sealing",
                        event.seq
                    ),
                });
            }
            global_prev = event.hash;
        }
        None
    }

    /// The rich first break on the global spine, or `None` — the detailed twin of `verify()`.
    pub fn first_break(&self) -> Option<ChainBreak> {
        self.locate_global_break()
    }

    /// A full [`IntegrityReport`]: the global status, every non-global chain's status (each with
    /// its [`ChainBreak`] when broken), the overall `healthy` flag, and the permanent re-anchor
    /// disclosure. This is the rich, structured verifier the api/store/web surface — `verify()`
    /// (the frozen `bool`/`Result` contract) stays exactly as-is alongside it.
    pub fn integrity_report(&self) -> IntegrityReport {
        let global = self
            .chain_status(&ChainId::Global)
            .expect("global chain always has a status");
        let chains = self.chains();
        let healthy =
            global.first_break.is_none() && chains.iter().all(|c| c.first_break.is_none());
        IntegrityReport {
            global,
            chains,
            healthy,
            reanchored_segments: self.reanchored_segments(),
        }
    }

    /// Alias for [`Ledger::integrity_report`] under the deliverable's `verify_detailed` name.
    pub fn verify_detailed(&self) -> IntegrityReport {
        self.integrity_report()
    }

    // ---- §2.3 validating append --------------------------------------------------------------

    /// A **validating** append: check the new event's would-be [`ChainLink`]s against the current
    /// head of every chain it joins (genesis-kind rules + a broken-tail guard) BEFORE mutating,
    /// then append exactly as [`Ledger::append`] would. On `Err` nothing is appended.
    ///
    /// **Perf (frozen):** this is `O(links)` hash work — it recomputes only the *head* event of
    /// each joined chain (plus the global tail) to detect a broken tail, and derives genesis rules
    /// from membership. It is deliberately **not** a whole-ledger re-verify (which is `O(n)` hash
    /// work and stays on load + [`Ledger::integrity_report`]). A break buried mid-chain that does
    /// not affect a joined chain's head is therefore not this method's job to catch — full verify
    /// on load owns that.
    // The `AppendError` size is intentional: `BrokenChainTail` carries a full `ChainBreak` (the
    // FROZEN contract §2.3 shape E2/E3 code against). Boxing would deviate from the frozen API.
    #[allow(clippy::result_large_err)]
    pub fn try_append(
        &mut self,
        actor: &str,
        scope: &str,
        kind: &str,
        justification: Option<&str>,
        payload: &[u8],
    ) -> Result<&Event, AppendError> {
        let memberships = Ledger::memberships(scope, kind);
        // Head event index per chain (one O(n) pointer scan, no hashing — as `append` already
        // does to build heads). The hashing below is bounded by O(links).
        let head_idx = self.head_event_indices();

        for chain in &memberships {
            match head_idx.get(chain) {
                // Empty chain ⇒ this event is its genesis: enforce the genesis-kind rule.
                None => {
                    if let Some(expected) = chain.expected_genesis_kind()
                        && kind != expected
                    {
                        return Err(AppendError::ChainGenesisWrong {
                            chain: chain.clone(),
                            expected: expected.to_owned(),
                            found: kind.to_owned(),
                        });
                    }
                }
                // Non-empty chain ⇒ its tail must self-verify, else we'd extend a broken chain.
                Some(&idx) => {
                    if let Some(b) = self.tail_break(chain, idx) {
                        return Err(AppendError::BrokenChainTail {
                            chain: chain.clone(),
                            break_: b,
                        });
                    }
                }
            }
        }
        // The global tail must also self-verify before we link a new event onto it.
        if let Some(idx) = self.events.len().checked_sub(1)
            && let Some(b) = self.tail_break(&ChainId::Global, idx)
        {
            return Err(AppendError::BrokenChainTail {
                chain: ChainId::Global,
                break_: b,
            });
        }

        let timestamp = OffsetDateTime::now_utc();
        Ok(self.append_at(actor, scope, kind, justification, payload, timestamp))
    }

    /// The head event index of every chain (global-order scan; no hashing). Used by
    /// [`Ledger::try_append`] to bound its tail check to `O(links)` hashes.
    fn head_event_indices(&self) -> HashMap<ChainId, usize> {
        let mut heads: HashMap<ChainId, usize> = HashMap::new();
        for (i, event) in self.events.iter().enumerate() {
            for link in &event.links {
                heads.insert(link.chain.clone(), i);
            }
        }
        heads
    }

    /// If the event at `idx` (the tail/head of `chain`) does not self-verify, return the break;
    /// else `None`. `O(1)` hash work — a single self-hash recomputation.
    fn tail_break(&self, chain: &ChainId, idx: usize) -> Option<ChainBreak> {
        let event = &self.events[idx];
        let recomputed = event.compute_hash(&event.prev_hash);
        if recomputed == event.hash {
            return None;
        }
        let chain_seq = event
            .links
            .iter()
            .find(|l| &l.chain == chain)
            .map(|l| l.seq);
        Some(ChainBreak {
            chain: chain.clone(),
            kind: BreakKind::HashMismatch,
            global_seq: Some(event.seq),
            chain_seq,
            event_id: Some(event.id),
            expected_hash: Some(recomputed),
            actual_hash: Some(event.hash),
            message: format!(
                "event hash mismatch at seq {}: contents were altered after sealing",
                event.seq
            ),
        })
    }

    // ---- §2.2 re-anchor ----------------------------------------------------------------------

    /// Re-anchor: rebuild every event's hashes IN PLACE from current event **content**, cascading
    /// the whole global spine so every affected chain is re-linked, then append a chained
    /// `ledger.reanchored` audit event disclosing it. Returns the [`ReanchorRecord`].
    ///
    /// This is the last-resort recovery primitive. It never drops, reorders, inserts, or edits
    /// event *content* (actor/scope/kind/timestamp/payload_digest are untouched) — it only
    /// recomputes the derivable linkage (global seq/prev_hash and each per-chain link) and the
    /// `hash`. Because the global spine threads every event, the rebuild cascades from the first
    /// divergence forward; all chains with a rebuilt member are named in `affected`.
    ///
    /// It is **never automatic** and refuses when the ledger already verifies
    /// ([`ReanchorError::AlreadyValid`]) or the `reason` is empty ([`ReanchorError::EmptyReason`]).
    /// `at` is caller-supplied (the core takes no clock). The disclosure is a chained audit event
    /// plus `pre_reanchor_digest` (a sha256 of the overwritten hashes), so the original broken
    /// state stays provable and the re-anchor can never silently erase evidence.
    pub fn reanchor(
        &mut self,
        actor: &str,
        reason: &str,
        at: OffsetDateTime,
    ) -> Result<ReanchorRecord, ReanchorError> {
        if reason.trim().is_empty() {
            return Err(ReanchorError::EmptyReason);
        }
        if self.verify().is_ok() {
            return Err(ReanchorError::AlreadyValid);
        }

        let original_global_head = self.head();
        // Snapshot the hashes about to be overwritten (proves what the rebuild replaced).
        let old_hashes: Vec<[u8; 32]> = self.events.iter().map(|e| e.hash).collect();

        // Rebuild the whole spine deterministically from content, exactly as append would derive
        // linkage — recompute global seq/prev_hash, canonical per-chain links, and the hash.
        let mut global_prev = [0u8; 32];
        let mut heads: HashMap<ChainId, (u64, [u8; 32])> = HashMap::new();
        for (index, event) in self.events.iter_mut().enumerate() {
            let seq = index as u64;
            let mut links: Vec<ChainLink> = Ledger::memberships(&event.scope, &event.kind)
                .into_iter()
                .map(|chain| {
                    let (link_seq, link_prev) = match heads.get(&chain) {
                        Some(&(head_seq, head_hash)) => (head_seq + 1, head_hash),
                        None => (0, [0u8; 32]),
                    };
                    ChainLink {
                        chain,
                        seq: link_seq,
                        prev_hash: link_prev,
                    }
                })
                .collect();
            links.sort_by(|a, b| a.chain.cmp(&b.chain));
            let hash = compute_hash(
                &global_prev,
                seq,
                &event.actor,
                &event.scope,
                &event.kind,
                event.timestamp,
                &event.payload_digest,
                &links,
            );
            for link in &links {
                heads.insert(link.chain.clone(), (link.seq, hash));
            }
            event.seq = seq;
            event.prev_hash = global_prev;
            event.links = links;
            event.hash = hash;
            global_prev = hash;
        }

        // Which chains changed, and over which chain-seq range (only rebuilt-and-changed members).
        let mut ranges: std::collections::BTreeMap<ChainId, (u64, u64)> =
            std::collections::BTreeMap::new();
        for (index, event) in self.events.iter().enumerate() {
            if old_hashes.get(index) == Some(&event.hash) {
                continue; // hash unchanged ⇒ this event was before the divergence.
            }
            for link in &event.links {
                let entry = ranges
                    .entry(link.chain.clone())
                    .or_insert((link.seq, link.seq));
                entry.0 = entry.0.min(link.seq);
                entry.1 = entry.1.max(link.seq);
            }
        }
        let affected: Vec<ReanchorSegment> = ranges
            .into_iter()
            .map(|(chain, (from, to))| ReanchorSegment {
                chain,
                from_chain_seq: from,
                to_chain_seq: to,
            })
            .collect();

        let new_global_head = self.head().expect("non-empty ledger after rebuild");
        let pre_reanchor_digest = {
            let mut hasher = Sha256::new();
            for h in &old_hashes {
                hasher.update(h);
            }
            hasher.finalize().into()
        };

        let record = ReanchorRecord {
            actor: actor.to_owned(),
            at,
            reason: reason.to_owned(),
            affected,
            original_global_head,
            new_global_head,
            pre_reanchor_digest,
        };

        // Disclose via a CHAINED audit event: digest the canonical record into `payload_digest`
        // (in the frozen preimage ⇒ tamper-evident) and retain the same JSON in `justification`
        // so `reanchored_segments()` can reconstruct the record permanently.
        let record_json =
            serde_json::to_string(&record).expect("ReanchorRecord serializes to JSON");
        self.append_at(
            actor,
            RECOVERY_SCOPE,
            REANCHOR_EVENT_KIND,
            Some(&record_json),
            record_json.as_bytes(),
            at,
        );

        // The rebuilt ledger + the appended disclosure must now verify cleanly.
        match self.verify() {
            Ok(_) => Ok(record),
            Err(e) => Err(ReanchorError::VerificationFailed(e)),
        }
    }

    /// The re-anchor records disclosed by the audit chain — permanent, derived from the chained
    /// `ledger.reanchored` events (never a separate mutable flag). A book appearing here is
    /// permanently distinguishable from an untouched one (contract §2.2 / §2.10).
    ///
    /// Each record is reconstructed from the event's retained `justification` JSON; its integrity
    /// is anchored because `payload_digest == digest(justification)` is committed in the frozen
    /// hash preimage, so a forged disclosure is detectable by [`Ledger::verify`].
    pub fn reanchored_segments(&self) -> Vec<ReanchorRecord> {
        self.events
            .iter()
            .filter(|e| e.kind == REANCHOR_EVENT_KIND && e.scope == RECOVERY_SCOPE)
            .filter_map(|e| {
                let json = e.justification.as_deref()?;
                // Only trust a disclosure whose retained JSON matches the committed digest.
                if digest(json.as_bytes()) != e.payload_digest {
                    return None;
                }
                serde_json::from_str::<ReanchorRecord>(json).ok()
            })
            .collect()
    }

    // ---- §2.6 standalone bundle-chain verification -------------------------------------------

    /// Verify a SINGLE `chain` over an isolated set of `events` (a per-book export bundle),
    /// checking each member's self-hash + that chain's seq/link/genesis — WITHOUT assuming
    /// global-spine seq continuity. Returns the chain length, or the precise first [`ChainBreak`].
    ///
    /// This is the import/export trust core: because a bundle carries only one chain's members
    /// (not the global spine), a recipient can independently verify it end-to-end. It is a free
    /// function over borrowed events (no `Ledger` needed).
    // `Result<u64, ChainBreak>` is the FROZEN contract §2.6 signature (import trusts on it);
    // boxing the `Err` would change the API E2 codes against.
    #[allow(clippy::result_large_err)]
    pub fn verify_bundle_chain(events: &[Event], chain: &ChainId) -> Result<u64, ChainBreak> {
        let mut state: Option<(u64, [u8; 32])> = None;
        let mut count = 0u64;
        for event in events {
            // A bundle carries one chain's members; the global chain (every event a member) is
            // supported for completeness by treating each event as its own member.
            let link = match event.links.iter().find(|l| &l.chain == chain) {
                Some(l) => l,
                None => continue,
            };
            let recomputed = event.compute_hash(&event.prev_hash);
            if recomputed != event.hash {
                return Err(ChainBreak {
                    chain: chain.clone(),
                    kind: BreakKind::HashMismatch,
                    global_seq: Some(event.seq),
                    chain_seq: Some(link.seq),
                    event_id: Some(event.id),
                    expected_hash: Some(recomputed),
                    actual_hash: Some(event.hash),
                    message: format!(
                        "event hash mismatch at seq {}: contents were altered after sealing",
                        event.seq
                    ),
                });
            }
            match state {
                None => {
                    if let Some(b) = genesis_break(chain, event, link) {
                        return Err(b);
                    }
                }
                Some((last_seq, last_hash)) => {
                    let expected = last_seq + 1;
                    if link.seq != expected {
                        return Err(ChainBreak {
                            chain: chain.clone(),
                            kind: BreakKind::ChainSequenceBroken,
                            global_seq: Some(event.seq),
                            chain_seq: Some(link.seq),
                            event_id: Some(event.id),
                            expected_hash: None,
                            actual_hash: None,
                            message: format!(
                                "chain {chain} sequence broken: expected chain-seq {expected}, \
                                 found {}",
                                link.seq
                            ),
                        });
                    }
                    if link.prev_hash != last_hash {
                        return Err(ChainBreak {
                            chain: chain.clone(),
                            kind: BreakKind::ChainLinkBroken,
                            global_seq: Some(event.seq),
                            chain_seq: Some(link.seq),
                            event_id: Some(event.id),
                            expected_hash: Some(last_hash),
                            actual_hash: Some(link.prev_hash),
                            message: format!(
                                "chain {chain} link broken at chain-seq {}: prev_hash does not \
                                 match preceding member",
                                link.seq
                            ),
                        });
                    }
                }
            }
            state = Some((link.seq, event.hash));
            count += 1;
        }
        Ok(count)
    }

    /// [`Ledger::verify_bundle_chain`] as an ergonomic [`BundleVerdict`] enum.
    pub fn verify_bundle_chain_verdict(events: &[Event], chain: &ChainId) -> BundleVerdict {
        match Ledger::verify_bundle_chain(events, chain) {
            Ok(length) => BundleVerdict::Verified { length },
            Err(break_) => BundleVerdict::Broken(break_),
        }
    }
}

/// The genesis-member break for `chain`, mirroring [`check_chain_genesis`] as a [`ChainBreak`].
///
/// Returns `None` when the (seq-0) genesis member is well-formed for the chain.
fn genesis_break(chain: &ChainId, event: &Event, link: &ChainLink) -> Option<ChainBreak> {
    if link.seq != 0 {
        return Some(ChainBreak {
            chain: chain.clone(),
            kind: BreakKind::ChainSequenceBroken,
            global_seq: Some(event.seq),
            chain_seq: Some(link.seq),
            event_id: Some(event.id),
            expected_hash: None,
            actual_hash: None,
            message: format!(
                "chain {chain} sequence broken: expected chain-seq 0, found {}",
                link.seq
            ),
        });
    }
    if link.prev_hash != [0u8; 32] {
        return Some(ChainBreak {
            chain: chain.clone(),
            kind: BreakKind::ChainLinkBroken,
            global_seq: Some(event.seq),
            chain_seq: Some(link.seq),
            event_id: Some(event.id),
            expected_hash: Some([0u8; 32]),
            actual_hash: Some(link.prev_hash),
            message: format!(
                "chain {chain} link broken at chain-seq 0: genesis prev_hash must be all-zero"
            ),
        });
    }
    if let Some(expected) = chain.expected_genesis_kind()
        && event.kind != expected
    {
        return Some(ChainBreak {
            chain: chain.clone(),
            kind: BreakKind::ChainGenesisWrong,
            global_seq: Some(event.seq),
            chain_seq: Some(link.seq),
            event_id: Some(event.id),
            expected_hash: None,
            actual_hash: None,
            message: format!(
                "chain {chain} genesis kind wrong: expected {expected:?}, found {:?}",
                event.kind
            ),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Realistic hierarchy identifiers (valid UUID strings) for the frozen scope grammar.
    const E1: &str = "11111111-1111-4111-8111-111111111111";
    const E2: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const B1: &str = "22222222-2222-4222-8222-222222222222";
    const B2: &str = "33333333-3333-4333-8333-333333333333";
    const A1: &str = "44444444-4444-4444-8444-444444444444";

    fn entity_scope(eid: &str) -> String {
        eid.to_owned()
    }
    fn book_scope(eid: &str, bid: &str) -> String {
        format!("entity:{eid}/book:{bid}")
    }
    fn act_scope(eid: &str, bid: &str, aid: &str) -> String {
        format!("entity:{eid}/book:{bid}/act:{aid}")
    }

    fn company(eid: &str) -> ChainId {
        ChainId::Company(eid.to_owned())
    }
    fn book(bid: &str) -> ChainId {
        ChainId::Book(bid.to_owned())
    }

    /// A small realistic ledger: entity → book (termo genesis) → two sealed acts, plus two
    /// application events (a setting and a user). 5 events total.
    fn sample_ledger() -> Ledger {
        let mut l = Ledger::new();
        l.append("mgr", &entity_scope(E1), "entity.created", None, b"entity");
        l.append("mgr", &book_scope(E1, B1), "book.opened", None, b"termo");
        l.append(
            "sec",
            &act_scope(E1, B1, A1),
            "act.sealed",
            Some("ata 1"),
            b"a1",
        );
        l.append("admin", "settings", "settings.updated", None, b"cfg");
        l.append("admin", "user", "user.created", None, b"user");
        l
    }

    // --- Basics / global spine -------------------------------------------------------------

    #[test]
    fn empty_ledger_verifies() {
        let ledger = Ledger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.verify(), Ok(0));
        assert_eq!(ledger.head(), None);
        assert!(ledger.chains().is_empty());
        // The global chain still has a status (empty).
        let g = ledger.chain_status(&ChainId::Global).unwrap();
        assert_eq!(g.length, 0);
        assert_eq!(g.head, None);
        assert!(g.verified);
    }

    #[test]
    fn genesis_has_zero_prev_hash() {
        let mut ledger = Ledger::new();
        let ev = ledger.append("alice", &book_scope(E1, B1), "book.opened", None, b"termo");
        assert_eq!(ev.seq, 0);
        assert_eq!(ev.prev_hash, [0u8; 32]);
        assert_ne!(ev.hash, [0u8; 32]);
        // Every non-global link at genesis also has a zero backward link.
        assert!(
            ev.links
                .iter()
                .all(|l| l.prev_hash == [0u8; 32] && l.seq == 0)
        );
    }

    #[test]
    fn append_chain_links_and_verifies() {
        let ledger = sample_ledger();
        assert_eq!(ledger.len(), 5);
        assert_eq!(ledger.verify(), Ok(5));
        // Each event links backward to the previous event's hash on the global spine.
        let events = ledger.events();
        for w in events.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].hash);
        }
        assert_eq!(ledger.head(), Some(events[4].hash));
    }

    #[test]
    fn payload_digest_matches_free_function() {
        let mut ledger = Ledger::new();
        let ev = ledger.append(
            "alice",
            "settings",
            "settings.updated",
            None,
            b"deliberations",
        );
        assert_eq!(ev.payload_digest, digest(b"deliberations"));
    }

    #[test]
    fn single_event_chain_verifies() {
        let mut ledger = Ledger::new();
        ledger.append("alice", &entity_scope(E1), "entity.created", None, b"e");
        assert_eq!(ledger.verify(), Ok(1));
        assert_eq!(ledger.verify_chain(&company(E1)), Ok(1));
        assert_eq!(ledger.verify_chain(&ChainId::Global), Ok(1));
    }

    #[test]
    fn subject_erased_attestation_appends_and_verifies() {
        // The GDPR right-to-erasure attestation (wp26-gdpr) is a normal append: it must take the
        // ledger from Ok(n) to Ok(n+1) with no mutation of any prior event, preserving tamper
        // evidence. Subject Amélia Marques (fictional) is erased from Encosto Estratégico Lda.
        let mut ledger = Ledger::new();
        // Seed some prior history so we prove verify() advances n -> n+1, not just 0 -> 1.
        ledger.append(
            "amelia.marques",
            &entity_scope(E1),
            "entity.created",
            None,
            b"e",
        );
        ledger.append(
            "amelia.marques",
            &book_scope(E1, B1),
            "book.opened",
            None,
            b"termo",
        );
        let n = ledger.verify().expect("pre-erasure ledger verifies");
        assert_eq!(n, 2);

        // Keyword `user:{uuid}` scope routes to the Application chain (no genesis-kind constraint);
        // actor is the subject UUID, not the username slug (pseudonymous-actor convention).
        let subject_uuid = E1;
        let scope = format!("user:{subject_uuid}");
        assert_eq!(
            Ledger::memberships(&scope, SUBJECT_ERASED_KIND),
            vec![ChainId::Application],
            "subject.erased must live on the Application chain",
        );
        let ev = ledger.append(
            subject_uuid,
            &scope,
            SUBJECT_ERASED_KIND,
            Some(r#"{"subject_id":"11111111-1111-4111-8111-111111111111","technique":["crypto_erase","physical_delete","vacuum"],"dek_destroyed":true}"#),
            b"subject-erasure-attestation",
        );
        assert_eq!(ev.kind, "subject.erased");
        assert_eq!(
            ev.actor, subject_uuid,
            "actor is the subject UUID, not a username slug"
        );

        // The whole ledger still verifies and the count advanced by exactly one.
        assert_eq!(ledger.verify(), Ok(n + 1));
        // The pre-existing chains are untouched (no reanchor, no rewrite): the Company(E1) chain
        // still holds exactly its two seed members (entity.created + book.opened).
        assert_eq!(ledger.verify_chain(&ChainId::Global), Ok(n + 1));
        assert_eq!(ledger.verify_chain(&company(E1)), Ok(2));
    }

    #[test]
    fn annotation_preserves_prior_sealed_events_byte_for_byte() {
        // Art. 17(3)(b): a sealed act's PII is retained; the remedy is an append-only annotation that
        // must NOT touch the sealed/signed event, so its hash (what a signature is computed over) stays
        // identical. Subject Amélia Marques of Encosto Estratégico Lda (fictional).
        let mut ledger = Ledger::new();
        ledger.append(
            "amelia.marques",
            &entity_scope(E1),
            "entity.created",
            None,
            b"e",
        );
        ledger.append(
            "amelia.marques",
            &book_scope(E1, B1),
            "book.opened",
            None,
            b"termo",
        );
        // The sealed act — the signed legal record whose bytes must never change.
        let sealed = ledger
            .append(
                "amelia.marques",
                &act_scope(E1, B1, A1),
                "act.sealed",
                Some("sealed minute naming the subject"),
                b"ata-payload",
            )
            .clone();
        let n = ledger.verify().expect("verifies before annotation");

        // Snapshot every event's frozen hash + payload_digest.
        let before: Vec<([u8; 32], [u8; 32])> = ledger
            .events()
            .iter()
            .map(|e| (e.hash, e.payload_digest))
            .collect();

        // Append the rectification annotation, scoped to the same act so it is discoverable alongside
        // the sealed record but is a NEW event at the chain head — never a rewrite.
        let annotation = ledger.append(
            "11111111-1111-4111-8111-111111111111",
            &act_scope(E1, B1, A1),
            SUBJECT_RECTIFICATION_KIND,
            Some(r#"{"field":"name","correction":"see rectification note"}"#),
            b"rectification-note",
        );
        assert_eq!(annotation.kind, "subject.rectification_noted");

        // The ledger still verifies at n+1 and every prior event is byte-identical (signatures valid).
        assert_eq!(ledger.verify(), Ok(n + 1));
        for (event, (hash, digest)) in ledger.events().iter().zip(before.iter()) {
            assert_eq!(event.hash, *hash, "prior event hash frozen");
            assert_eq!(
                event.payload_digest, *digest,
                "prior event payload_digest frozen"
            );
        }
        // The sealed act specifically is untouched.
        let sealed_now = ledger
            .events()
            .iter()
            .find(|e| e.id == sealed.id)
            .expect("sealed act still present");
        assert_eq!(
            sealed_now, &sealed,
            "sealed act event is byte-identical after annotation"
        );
    }

    // --- Membership derivation (frozen §3.2 grammar) ---------------------------------------

    #[test]
    fn membership_uuid_scope_yields_company() {
        assert_eq!(
            Ledger::memberships(&entity_scope(E1), "entity.created"),
            vec![company(E1)]
        );
    }

    #[test]
    fn membership_book_scope_yields_company_and_book_canonically_ordered() {
        // Canonical order: "book:.." sorts before "company:..".
        assert_eq!(
            Ledger::memberships(&book_scope(E1, B1), "book.opened"),
            vec![book(B1), company(E1)]
        );
    }

    #[test]
    fn membership_act_scope_yields_company_and_book() {
        assert_eq!(
            Ledger::memberships(&act_scope(E1, B1, A1), "act.sealed"),
            vec![book(B1), company(E1)]
        );
    }

    #[test]
    fn membership_tenant_segment_adds_a_tenant_chain_additively() {
        const T1: &str = "77777777-7777-4777-8777-777777777777";
        // A tenant-scoped entity event joins BOTH the tenant chain and the company chain.
        // Canonical order sorts "company:.." before "tenant:..".
        assert_eq!(
            Ledger::memberships(&format!("tenant:{T1}/entity:{E1}"), "entity.created"),
            vec![company(E1), ChainId::Tenant(T1.to_owned())]
        );
        // A bare tenant scope yields just the tenant chain — never the application fallback.
        assert_eq!(
            Ledger::memberships(&format!("tenant:{T1}"), "tenant.created"),
            vec![ChainId::Tenant(T1.to_owned())]
        );
        // Round-trip through the canonical string.
        assert_eq!(
            format!("tenant:{T1}").parse::<ChainId>().unwrap(),
            ChainId::Tenant(T1.to_owned())
        );
    }

    #[test]
    fn membership_app_keyword_scopes_yield_application() {
        for scope in ["settings", "cae", "law", "user", "backup"] {
            assert_eq!(
                Ledger::memberships(scope, "whatever"),
                vec![ChainId::Application],
                "scope {scope} should be the application chain"
            );
        }
    }

    #[test]
    fn membership_entityless_book_scope_yields_book_only() {
        // The `book:{bid}/act:{aid}` fallback (entity id unresolved) routes to the book chain,
        // never to application — the app-audit / book-action split is honoured.
        assert_eq!(
            Ledger::memberships(&format!("book:{B1}/act:{A1}"), "act.advanced"),
            vec![book(B1)]
        );
    }

    #[test]
    fn application_and_book_chains_are_disjoint() {
        // The literal "different things": no scope yields both Application and a company/book.
        let app = Ledger::memberships("settings", "settings.updated");
        assert!(
            !app.iter()
                .any(|c| matches!(c, ChainId::Company(_) | ChainId::Book(_)))
        );
        let bookish = Ledger::memberships(&book_scope(E1, B1), "book.opened");
        assert!(!bookish.contains(&ChainId::Application));
    }

    // --- Per-chain lineage correctness -----------------------------------------------------

    #[test]
    fn per_chain_sequences_and_linkage_are_correct() {
        let ledger = sample_ledger();
        assert_eq!(ledger.verify(), Ok(5));

        // Company E1: entity.created (0), book.opened (1), act.sealed (2).
        assert_eq!(ledger.chain_length(&company(E1)), 3);
        assert_eq!(ledger.verify_chain(&company(E1)), Ok(3));
        // Book B1: book.opened (0), act.sealed (1).
        assert_eq!(ledger.chain_length(&book(B1)), 2);
        assert_eq!(ledger.verify_chain(&book(B1)), Ok(2));
        // Application: settings.updated (0), user.created (1).
        assert_eq!(ledger.chain_length(&ChainId::Application), 2);
        assert_eq!(ledger.verify_chain(&ChainId::Application), Ok(2));

        // The book chain's members carry chain-seq 0,1 with correct backward links.
        let members = ledger.events_in_chain(&book(B1));
        let l0 = members[0]
            .links
            .iter()
            .find(|l| l.chain == book(B1))
            .unwrap();
        let l1 = members[1]
            .links
            .iter()
            .find(|l| l.chain == book(B1))
            .unwrap();
        assert_eq!((l0.seq, l0.prev_hash), (0, [0u8; 32]));
        assert_eq!((l1.seq, l1.prev_hash), (1, members[0].hash));
        assert_eq!(ledger.chain_head(&book(B1)), Some(members[1].hash));
    }

    #[test]
    fn company_chain_spans_multiple_books() {
        let mut l = Ledger::new();
        l.append("mgr", &entity_scope(E1), "entity.created", None, b"e");
        l.append("mgr", &book_scope(E1, B1), "book.opened", None, b"t1");
        l.append("mgr", &book_scope(E1, B2), "book.opened", None, b"t2");
        l.append("sec", &act_scope(E1, B1, A1), "act.sealed", None, b"a1");
        assert_eq!(l.verify(), Ok(4));

        // The company chain threads both books' events; each book chain is independent.
        assert_eq!(l.verify_chain(&company(E1)), Ok(4));
        assert_eq!(l.chain_length(&book(B1)), 2); // opened + act
        assert_eq!(l.chain_length(&book(B2)), 1); // opened only
        assert_eq!(l.verify_chain(&book(B1)), Ok(2));
        assert_eq!(l.verify_chain(&book(B2)), Ok(1));
    }

    #[test]
    fn application_chain_accumulates_across_kinds() {
        let mut l = Ledger::new();
        l.append("a", "settings", "settings.updated", None, b"1");
        l.append("a", "user", "user.created", None, b"2");
        l.append("a", "cae", "cae.updated", None, b"3");
        l.append("a", "law", "law.fetched", None, b"4");
        l.append("a", "backup", "backup.created", None, b"5");
        assert_eq!(l.verify(), Ok(5));
        // A single application chain of length 5 regardless of the differing app kinds/scopes.
        assert_eq!(l.chain_length(&ChainId::Application), 5);
        assert_eq!(l.verify_chain(&ChainId::Application), Ok(5));
        // No company/book chains exist.
        assert!(l.chains().iter().all(|c| c.chain == ChainId::Application));
    }

    #[test]
    fn links_are_stored_in_canonical_order() {
        let mut l = Ledger::new();
        let ev = l.append("mgr", &book_scope(E1, B1), "book.opened", None, b"t");
        // Book before Company (canonical string order).
        assert_eq!(ev.links.len(), 2);
        assert_eq!(ev.links[0].chain, book(B1));
        assert_eq!(ev.links[1].chain, company(E1));
    }

    // --- THE ISOLATION PROOFS --------------------------------------------------------------

    #[test]
    fn tampering_a_book_act_breaks_book_company_global_but_not_application() {
        let mut l = sample_ledger();
        assert_eq!(l.verify(), Ok(5));

        // Flip the content of the sealed act event (global seq 2) without re-signing its hash.
        l.events[2].payload_digest = digest(b"forged");

        // The book, company, and global chains that include event 2 are broken at seq 2.
        assert_eq!(
            l.verify_chain(&book(B1)),
            Err(LedgerError::HashMismatch { seq: 2 })
        );
        assert_eq!(
            l.verify_chain(&company(E1)),
            Err(LedgerError::HashMismatch { seq: 2 })
        );
        assert_eq!(
            l.verify_chain(&ChainId::Global),
            Err(LedgerError::HashMismatch { seq: 2 })
        );
        // The application chain does NOT include event 2 — it verifies cleanly.
        assert_eq!(l.verify_chain(&ChainId::Application), Ok(2));
    }

    #[test]
    fn tampering_a_settings_event_breaks_application_global_but_not_company_book() {
        let mut l = sample_ledger();
        assert_eq!(l.verify(), Ok(5));

        // Flip the content of the settings event (global seq 3).
        l.events[3].payload_digest = digest(b"forged");

        assert_eq!(
            l.verify_chain(&ChainId::Application),
            Err(LedgerError::HashMismatch { seq: 3 })
        );
        assert_eq!(
            l.verify_chain(&ChainId::Global),
            Err(LedgerError::HashMismatch { seq: 3 })
        );
        // The company and book chains do NOT include the settings event — they stay valid.
        assert_eq!(l.verify_chain(&company(E1)), Ok(3));
        assert_eq!(l.verify_chain(&book(B1)), Ok(2));
    }

    // --- Genesis-kind assertions (WFL-11) --------------------------------------------------

    #[test]
    fn book_chain_genesis_must_be_book_opened() {
        // First (and only) event of a book chain is an act.sealed, not book.opened.
        let mut l = Ledger::new();
        l.append(
            "sec",
            &format!("book:{B1}/act:{A1}"),
            "act.sealed",
            None,
            b"a",
        );
        assert_eq!(
            l.verify(),
            Err(LedgerError::ChainGenesisWrong {
                chain: book(B1),
                expected: "book.opened".to_owned(),
                found: "act.sealed".to_owned(),
            })
        );
        assert_eq!(
            l.verify_chain(&book(B1)),
            Err(LedgerError::ChainGenesisWrong {
                chain: book(B1),
                expected: "book.opened".to_owned(),
                found: "act.sealed".to_owned(),
            })
        );
    }

    #[test]
    fn company_chain_genesis_must_be_entity_created() {
        let mut l = Ledger::new();
        l.append("mgr", &entity_scope(E1), "entity.updated", None, b"e");
        assert_eq!(
            l.verify(),
            Err(LedgerError::ChainGenesisWrong {
                chain: company(E1),
                expected: "entity.created".to_owned(),
                found: "entity.updated".to_owned(),
            })
        );
    }

    #[test]
    fn application_chain_has_no_genesis_kind_constraint() {
        // Any first kind is acceptable on the application chain.
        let mut l = Ledger::new();
        l.append("a", "user", "user.some_novel_kind", None, b"u");
        assert_eq!(l.verify(), Ok(1));
        assert_eq!(l.verify_chain(&ChainId::Application), Ok(1));
    }

    // --- Global tamper detection -----------------------------------------------------------

    #[test]
    fn tamper_with_payload_digest_is_detected() {
        let mut l = sample_ledger();
        l.events[1].payload_digest = digest(b"forged");
        assert_eq!(l.verify(), Err(LedgerError::HashMismatch { seq: 1 }));
    }

    #[test]
    fn tamper_with_actor_is_detected() {
        let mut l = sample_ledger();
        l.events[0].actor = "mallory".to_owned();
        assert_eq!(l.verify(), Err(LedgerError::HashMismatch { seq: 0 }));
    }

    #[test]
    fn tamper_with_order_is_detected() {
        // Three application events (no genesis-kind constraint), then swap two.
        let mut l = Ledger::new();
        l.append("a", "settings", "settings.updated", None, b"a");
        l.append("a", "user", "user.created", None, b"b");
        l.append("a", "cae", "cae.updated", None, b"c");
        assert_eq!(l.verify(), Ok(3));

        l.events.swap(1, 2);
        match l.verify() {
            Err(LedgerError::SequenceBroken {
                index: 1,
                expected: 1,
                found: 2,
            }) => {}
            other => panic!("expected SequenceBroken at index 1, got {other:?}"),
        }
    }

    #[test]
    fn dropping_an_event_breaks_the_chain() {
        let mut l = Ledger::new();
        l.append("a", "settings", "settings.updated", None, b"a");
        l.append("a", "user", "user.created", None, b"b");
        l.append("a", "cae", "cae.updated", None, b"c");

        l.events.remove(1);
        assert_eq!(
            l.verify(),
            Err(LedgerError::SequenceBroken {
                index: 1,
                expected: 1,
                found: 2,
            })
        );
    }

    #[test]
    fn forged_genesis_prev_hash_is_detected() {
        let mut l = Ledger::new();
        l.append("a", &entity_scope(E1), "entity.created", None, b"a");
        let forged_prev = [7u8; 32];
        l.events[0].prev_hash = forged_prev;
        l.events[0].hash = l.events[0].compute_hash(&forged_prev);
        assert_eq!(l.verify(), Err(LedgerError::BadGenesis));
    }

    #[test]
    fn broken_backward_link_is_detected() {
        let mut l = sample_ledger();
        // Repoint seq-1's global backward link, leaving its own hash stale, so the global linkage
        // check (not the self-hash check) fires first.
        l.events[1].prev_hash = [0xAB; 32];
        assert_eq!(l.verify(), Err(LedgerError::LinkBroken { seq: 1 }));
    }

    // --- Per-chain tamper detection (link / sequence, self-hash kept consistent) -----------

    #[test]
    fn per_chain_link_broken_is_detected() {
        let mut l = sample_ledger();
        // Repoint the book link's backward hash on the act event (book chain-seq 1) to garbage,
        // and re-sign the event's hash so it is self-consistent — the per-chain link check, not
        // the self-hash check, is what must fire.
        let idx = 2; // act.sealed
        let link_pos = l.events[idx]
            .links
            .iter()
            .position(|link| link.chain == book(B1))
            .unwrap();
        l.events[idx].links[link_pos].prev_hash = [0xCD; 32];
        let prev = l.events[idx].prev_hash;
        l.events[idx].hash = l.events[idx].compute_hash(&prev);

        assert_eq!(
            l.verify_chain(&book(B1)),
            Err(LedgerError::ChainLinkBroken {
                chain: book(B1),
                seq: 1,
            })
        );
    }

    #[test]
    fn per_chain_sequence_broken_is_detected() {
        let mut l = sample_ledger();
        // Bump the book link's chain-seq on the act event from 1 to 5, re-signing the hash.
        let idx = 2;
        let link_pos = l.events[idx]
            .links
            .iter()
            .position(|link| link.chain == book(B1))
            .unwrap();
        l.events[idx].links[link_pos].seq = 5;
        let prev = l.events[idx].prev_hash;
        l.events[idx].hash = l.events[idx].compute_hash(&prev);

        assert_eq!(
            l.verify_chain(&book(B1)),
            Err(LedgerError::ChainSequenceBroken {
                chain: book(B1),
                expected: 1,
                found: 5,
            })
        );
    }

    // --- verify_chain / chains / status ----------------------------------------------------

    #[test]
    fn verify_chain_global_equals_verify_on_a_sound_ledger() {
        let l = sample_ledger();
        assert_eq!(l.verify_chain(&ChainId::Global), l.verify());
    }

    #[test]
    fn chains_lists_all_non_global_with_status() {
        let l = sample_ledger();
        let chains = l.chains();
        // application + company(E1) + book(B1) = 3 non-global chains.
        assert_eq!(chains.len(), 3);
        assert!(chains.iter().all(|c| c.verified));

        let app = chains
            .iter()
            .find(|c| c.chain == ChainId::Application)
            .unwrap();
        assert_eq!(app.length, 2);
        assert_eq!(app.genesis_kind.as_deref(), Some("settings.updated"));

        let comp = chains.iter().find(|c| c.chain == company(E1)).unwrap();
        assert_eq!(comp.length, 3);
        assert_eq!(comp.genesis_kind.as_deref(), Some("entity.created"));

        let bk = chains.iter().find(|c| c.chain == book(B1)).unwrap();
        assert_eq!(bk.length, 2);
        assert_eq!(bk.genesis_kind.as_deref(), Some("book.opened"));
        assert_eq!(bk.head, l.chain_head(&book(B1)));
    }

    #[test]
    fn chains_are_returned_in_canonical_order() {
        let mut l = Ledger::new();
        l.append("m", &entity_scope(E2), "entity.created", None, b"e2");
        l.append("m", &entity_scope(E1), "entity.created", None, b"e1");
        l.append("m", &book_scope(E1, B1), "book.opened", None, b"t");
        l.append("a", "settings", "settings.updated", None, b"s");
        let ids: Vec<String> = l
            .chains()
            .into_iter()
            .map(|c| c.chain.to_string())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "chains() must be canonically ordered");
    }

    #[test]
    fn chain_status_reflects_a_broken_chain() {
        let mut l = sample_ledger();
        l.events[2].payload_digest = digest(b"forged");
        let bk = l.chain_status(&book(B1)).unwrap();
        assert!(!bk.verified);
        let app = l.chain_status(&ChainId::Application).unwrap();
        assert!(app.verified);
    }

    #[test]
    fn chain_status_is_none_for_absent_chain() {
        let l = sample_ledger();
        assert!(l.chain_status(&book(B2)).is_none());
        assert!(l.chain_status(&company(E2)).is_none());
    }

    // --- ChainId string / serde ------------------------------------------------------------

    #[test]
    fn chain_id_canonical_strings_round_trip() {
        for (id, s) in [
            (ChainId::Global, "global"),
            (ChainId::Application, "application"),
            (company(E1), &*format!("company:{E1}")),
            (book(B1), &*format!("book:{B1}")),
        ] {
            assert_eq!(id.to_string(), s);
            assert_eq!(s.parse::<ChainId>().unwrap(), id);
        }
    }

    #[test]
    fn chain_id_rejects_malformed_strings() {
        assert!("company:".parse::<ChainId>().is_err());
        assert!("book:".parse::<ChainId>().is_err());
        assert!("nonsense".parse::<ChainId>().is_err());
    }

    #[test]
    fn chain_id_serializes_as_canonical_string() {
        let json = serde_json::to_string(&company(E1)).unwrap();
        assert_eq!(json, format!("\"company:{E1}\""));
        let back: ChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, company(E1));
    }

    // --- serde round-trips -----------------------------------------------------------------

    #[test]
    fn event_serde_round_trips_including_links() {
        let mut l = Ledger::new();
        l.append("mgr", &entity_scope(E1), "entity.created", None, b"e");
        l.append("mgr", &book_scope(E1, B1), "book.opened", Some("why"), b"t");
        let ev = &l.events()[1];
        assert_eq!(ev.links.len(), 2);
        let json = serde_json::to_string(ev).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, ev);
    }

    #[test]
    fn whole_ledger_serde_round_trips_and_reverifies() {
        let l = sample_ledger();
        let json = serde_json::to_string(&l).unwrap();
        let back: Ledger = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verify(), Ok(5));
        assert_eq!(back.events(), l.events());
    }

    // --- try_from_events -------------------------------------------------------------------

    #[test]
    fn try_from_events_empty_yields_empty_ledger() {
        let (ledger, status) = Ledger::try_from_events(Vec::new());
        assert!(ledger.is_empty());
        assert_eq!(ledger.head(), None);
        assert_eq!(status, Ok(0));
    }

    #[test]
    fn try_from_events_round_trips_through_serialization() {
        let original = sample_ledger();
        let json = serde_json::to_string(original.events()).unwrap();
        let persisted: Vec<Event> = serde_json::from_str(&json).unwrap();

        let (ledger, status) = Ledger::try_from_events(persisted);
        assert_eq!(status, Ok(5));
        assert_eq!(ledger.verify(), Ok(5));
        assert_eq!(ledger.events(), original.events());
        // Per-chain lineage survives the rebuild.
        assert_eq!(ledger.verify_chain(&book(B1)), Ok(2));
        assert_eq!(ledger.verify_chain(&company(E1)), Ok(3));
        assert_eq!(ledger.verify_chain(&ChainId::Application), Ok(2));
    }

    #[test]
    fn try_from_events_adopts_hashes_without_re_hashing() {
        let mut original = Ledger::new();
        // A valid single-event ledger: the company chain's genesis is `entity.created`
        // (this test exercises hash adoption, not genesis rules — which have their own test).
        original.append("mgr", &entity_scope(E1), "entity.created", None, b"t");
        let persisted = original.events().to_vec();

        let (ledger, status) = Ledger::try_from_events(persisted.clone());
        assert_eq!(status, Ok(1));
        assert_eq!(ledger.events(), persisted.as_slice());
    }

    #[test]
    fn try_from_events_rejects_hash_mismatch() {
        let mut l = sample_ledger();
        let mut events = l.events().to_vec();
        events[2].payload_digest = digest(b"forged");
        let (rebuilt, status) = Ledger::try_from_events(events);
        assert_eq!(status, Err(LedgerError::HashMismatch { seq: 2 }));
        assert_eq!(rebuilt.len(), 5);
        // (touch `l` so the binding is meaningfully mutable-free)
        let _ = &mut l;
    }

    #[test]
    fn try_from_events_rejects_bad_genesis() {
        let mut original = Ledger::new();
        original.append("mgr", &entity_scope(E1), "entity.created", None, b"e");
        let mut events = original.events().to_vec();
        let forged_prev = [7u8; 32];
        events[0].prev_hash = forged_prev;
        events[0].hash = events[0].compute_hash(&forged_prev);
        let (_, status) = Ledger::try_from_events(events);
        assert_eq!(status, Err(LedgerError::BadGenesis));
    }

    #[test]
    fn try_from_events_rejects_broken_sequence() {
        let mut l = Ledger::new();
        l.append("a", "settings", "settings.updated", None, b"a");
        l.append("a", "user", "user.created", None, b"b");
        l.append("a", "cae", "cae.updated", None, b"c");
        let mut events = l.events().to_vec();
        events.remove(1);
        let (_, status) = Ledger::try_from_events(events);
        assert_eq!(
            status,
            Err(LedgerError::SequenceBroken {
                index: 1,
                expected: 1,
                found: 2,
            })
        );
    }

    #[test]
    fn try_from_events_rejects_broken_link() {
        let mut l = sample_ledger();
        let mut events = l.events().to_vec();
        events[1].prev_hash = [0xAB; 32];
        let (_, status) = Ledger::try_from_events(events);
        assert_eq!(status, Err(LedgerError::LinkBroken { seq: 1 }));
        let _ = &mut l;
    }

    #[test]
    fn try_from_events_rejects_chain_genesis_wrong() {
        let mut original = Ledger::new();
        original.append(
            "sec",
            &format!("book:{B1}/act:{A1}"),
            "act.sealed",
            None,
            b"a",
        );
        let events = original.events().to_vec();
        let (_, status) = Ledger::try_from_events(events);
        assert_eq!(
            status,
            Err(LedgerError::ChainGenesisWrong {
                chain: book(B1),
                expected: "book.opened".to_owned(),
                found: "act.sealed".to_owned(),
            })
        );
    }

    // =========================================================================================
    // t54 — break-location / try_append / reanchor / verify_bundle_chain (ADDITIVE).
    // =========================================================================================

    fn fixed_time() -> OffsetDateTime {
        // A stable, caller-supplied instant (no core clock) for deterministic recovery tests.
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    // --- §2.1 break location (verify_detailed / locate_break) --------------------------------

    #[test]
    fn healthy_ledger_reports_no_break() {
        let l = sample_ledger();
        assert!(l.locate_break(&ChainId::Global).is_none());
        assert!(l.first_break().is_none());
        let report = l.verify_detailed();
        assert!(report.healthy);
        assert!(report.global.first_break.is_none());
        assert!(report.chains.iter().all(|c| c.first_break.is_none()));
        assert!(report.reanchored_segments.is_empty());
        // The detailed report agrees with the frozen bool contract.
        assert_eq!(report.healthy, l.verify().is_ok());
    }

    #[test]
    fn verify_detailed_pinpoints_a_synthesized_break() {
        let mut l = sample_ledger();
        // Tamper the sealed act (global seq 2), which belongs to book, company and global chains.
        let victim_id = l.events[2].id;
        let stored_hash = l.events[2].hash;
        l.events[2].payload_digest = digest(b"forged");
        let expected_recompute = l.events[2].compute_hash(&l.events[2].prev_hash);

        // Global spine: exact chain / seq / event-id / expected-vs-actual hash.
        let gb = l.locate_break(&ChainId::Global).expect("global break");
        assert_eq!(gb.chain, ChainId::Global);
        assert_eq!(gb.kind, BreakKind::HashMismatch);
        assert_eq!(gb.global_seq, Some(2));
        assert_eq!(gb.event_id, Some(victim_id));
        assert_eq!(gb.expected_hash, Some(expected_recompute));
        assert_eq!(gb.actual_hash, Some(stored_hash));

        // Book chain pinpoints the same event at its chain-seq 1.
        let bb = l.locate_break(&book(B1)).expect("book break");
        assert_eq!(bb.kind, BreakKind::HashMismatch);
        assert_eq!(bb.global_seq, Some(2));
        assert_eq!(bb.chain_seq, Some(1));
        assert_eq!(bb.event_id, Some(victim_id));

        // The whole report is unhealthy; the untouched application chain has no break.
        let report = l.verify_detailed();
        assert!(!report.healthy);
        assert!(report.global.first_break.is_some());
        let app = report
            .chains
            .iter()
            .find(|c| c.chain == ChainId::Application)
            .unwrap();
        assert!(app.first_break.is_none());
        let bk = report.chains.iter().find(|c| c.chain == book(B1)).unwrap();
        assert_eq!(
            bk.first_break.as_ref().map(|b| b.kind),
            Some(BreakKind::HashMismatch)
        );
    }

    #[test]
    fn locate_break_matches_verify_chain_across_break_kinds() {
        // For each kind of break, locate_break(chain).is_none() == verify_chain(chain).is_ok().
        // (a) sequence break on the global spine
        {
            let mut l = Ledger::new();
            l.append("a", "settings", "settings.updated", None, b"a");
            l.append("a", "user", "user.created", None, b"b");
            l.events.swap(0, 1);
            assert_eq!(
                l.locate_break(&ChainId::Global).map(|b| b.kind),
                Some(BreakKind::SequenceBroken)
            );
            assert!(l.verify().is_err());
        }
        // (b) bad genesis prev_hash
        {
            let mut l = Ledger::new();
            l.append("a", &entity_scope(E1), "entity.created", None, b"e");
            let forged = [7u8; 32];
            l.events[0].prev_hash = forged;
            l.events[0].hash = l.events[0].compute_hash(&forged);
            let b = l.locate_break(&ChainId::Global).unwrap();
            assert_eq!(b.kind, BreakKind::BadGenesis);
        }
        // (c) per-chain link break (self-hash kept consistent)
        {
            let mut l = sample_ledger();
            let idx = 2;
            let pos = l.events[idx]
                .links
                .iter()
                .position(|link| link.chain == book(B1))
                .unwrap();
            l.events[idx].links[pos].prev_hash = [0xCD; 32];
            let prev = l.events[idx].prev_hash;
            l.events[idx].hash = l.events[idx].compute_hash(&prev);
            let b = l.locate_break(&book(B1)).unwrap();
            assert_eq!(b.kind, BreakKind::ChainLinkBroken);
            assert_eq!(b.chain_seq, Some(1));
            assert_eq!(b.actual_hash, Some([0xCD; 32]));
        }
    }

    // --- §2.3 try_append ---------------------------------------------------------------------

    #[test]
    fn try_append_accepts_a_valid_link_and_matches_append() {
        let mut l = Ledger::new();
        l.append("mgr", &entity_scope(E1), "entity.created", None, b"e");
        let ev = l
            .try_append("mgr", &book_scope(E1, B1), "book.opened", None, b"termo")
            .expect("valid append accepted");
        assert_eq!(ev.seq, 1);
        // Book before Company canonical order, correct genesis linkage.
        assert_eq!(ev.links.len(), 2);
        assert_eq!(ev.links[0].chain, book(B1));
        assert_eq!(ev.links[0].seq, 0);
        assert_eq!(ev.links[0].prev_hash, [0u8; 32]);
        assert_eq!(l.verify(), Ok(2));
    }

    #[test]
    fn try_append_rejects_genesis_kind_violation() {
        let mut l = Ledger::new();
        // A book chain whose first event is not `book.opened` — rejected before mutating.
        let err = l
            .try_append(
                "sec",
                &format!("book:{B1}/act:{A1}"),
                "act.sealed",
                None,
                b"a",
            )
            .unwrap_err();
        assert_eq!(
            err,
            AppendError::ChainGenesisWrong {
                chain: book(B1),
                expected: "book.opened".to_owned(),
                found: "act.sealed".to_owned(),
            }
        );
        // Nothing was appended.
        assert!(l.is_empty());
        assert_eq!(l.verify(), Ok(0));
    }

    #[test]
    fn try_append_rejects_company_genesis_kind_violation() {
        let mut l = Ledger::new();
        let err = l
            .try_append("mgr", &entity_scope(E1), "entity.updated", None, b"e")
            .unwrap_err();
        assert!(matches!(err, AppendError::ChainGenesisWrong { .. }));
        assert!(l.is_empty());
    }

    #[test]
    fn try_append_rejects_appending_onto_a_broken_tail() {
        let mut l = Ledger::new();
        l.append("a", "settings", "settings.updated", None, b"a");
        l.append("a", "user", "user.created", None, b"b");
        // Corrupt the current application tail (its stored hash no longer matches its content).
        l.events[1].payload_digest = digest(b"forged");
        let err = l
            .try_append("a", "cae", "cae.updated", None, b"c")
            .unwrap_err();
        match err {
            AppendError::BrokenChainTail { chain, break_ } => {
                // The application chain (or the global tail) is named with the broken event.
                assert!(chain == ChainId::Application || chain == ChainId::Global);
                assert_eq!(break_.kind, BreakKind::HashMismatch);
                assert_eq!(break_.global_seq, Some(1));
            }
            other => panic!("expected BrokenChainTail, got {other:?}"),
        }
        // Rejected pre-commit: still only the two (one corrupt) events, no third appended.
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn try_append_is_a_tail_check_not_a_full_reverify() {
        // Structural proof of O(links): a break buried BEFORE the tail of the chain being joined
        // is NOT caught by try_append (a full O(n) re-verify would catch it). This pins the
        // perf-frozen tail-only semantics without any wall-clock timing.
        let mut l = sample_ledger(); // seqs: 0 entity,1 book.opened,2 act,3 settings,4 user
        // Tamper an event that is NOT the head of the chain we will append onto (application).
        // The application head is event 4 (intact); event 0 is the company E1 genesis.
        l.events[0].payload_digest = digest(b"forged-but-buried");
        // A full verify sees the break at seq 0; try_append onto the application chain does not,
        // because that chain's tail (event 4) still self-verifies.
        assert!(l.verify().is_err());
        let ev = l
            .try_append("admin", "settings", "settings.updated", None, b"cfg2")
            .expect("tail-only check accepts append onto an intact application tail");
        assert_eq!(ev.seq, 5);
        // Proof it was O(links): the buried break is still present (try_append did not scan it).
        assert!(l.verify().is_err());
    }

    // --- §2.2 reanchor -----------------------------------------------------------------------

    #[test]
    fn reanchor_errors_on_an_already_valid_ledger() {
        let mut l = sample_ledger();
        assert_eq!(
            l.reanchor("amelia.marques", "no reason", fixed_time()),
            Err(ReanchorError::AlreadyValid)
        );
    }

    #[test]
    fn reanchor_errors_on_empty_reason() {
        let mut l = sample_ledger();
        l.events[2].payload_digest = digest(b"forged"); // break it first
        assert_eq!(
            l.reanchor("amelia.marques", "   ", fixed_time()),
            Err(ReanchorError::EmptyReason)
        );
    }

    #[test]
    fn reanchor_repairs_a_broken_chain_and_discloses_it() {
        let mut l = sample_ledger();
        // Preserve the original content we must NOT lose.
        let original_content: Vec<(String, String)> = l
            .events()
            .iter()
            .map(|e| (e.actor.clone(), e.scope.clone()))
            .collect();
        // Break the sealed act (content forged, hash left stale ⇒ HashMismatch).
        l.events[2].payload_digest = digest(b"forged");
        let broken_head = l.head();
        assert!(l.verify().is_err());

        let record = l
            .reanchor(
                "amelia.marques",
                "backup unavailable; last resort",
                fixed_time(),
            )
            .expect("re-anchor succeeds on a broken ledger");

        // The ledger now verifies cleanly (rebuild + the appended disclosure event).
        assert!(l.verify().is_ok());
        assert!(l.verify_detailed().healthy);

        // Content preserved for the original 5 events: re-anchor rebuilds hashes/links, never
        // content — actor/scope survive verbatim and the sealed act still carries the content it
        // had (nothing silently erased).
        for (i, (actor, scope)) in original_content.iter().enumerate() {
            assert_eq!(&l.events()[i].actor, actor);
            assert_eq!(&l.events()[i].scope, scope);
        }
        assert_eq!(l.events()[2].payload_digest, digest(b"forged"));

        // Record fields.
        assert_eq!(record.actor, "amelia.marques");
        assert_eq!(record.at, fixed_time());
        assert_eq!(record.original_global_head, broken_head);
        assert_ne!(record.pre_reanchor_digest, [0u8; 32]);
        assert!(!record.affected.is_empty());
        // The book chain (which contained the broken act) is disclosed as affected.
        assert!(record.affected.iter().any(|s| s.chain == book(B1)));

        // A chained `ledger.reanchored` audit event now exists on the application chain.
        let audit = l
            .events()
            .iter()
            .find(|e| e.kind == REANCHOR_EVENT_KIND)
            .expect("reanchored audit event appended");
        assert_eq!(audit.scope, RECOVERY_SCOPE);
        assert!(
            audit
                .links
                .iter()
                .any(|link| link.chain == ChainId::Application)
        );

        // reanchored_segments() derives the permanent disclosure from the chained event.
        let segments = l.reanchored_segments();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0], record);

        // The disclosure survives a serialize/reload round-trip (permanent).
        let (reloaded, status) = Ledger::try_from_events(l.events().to_vec());
        assert!(status.is_ok());
        assert_eq!(reloaded.reanchored_segments(), vec![record]);
    }

    #[test]
    fn reanchor_never_automatic_requires_explicit_call() {
        // A break does NOT self-heal: only an explicit reanchor() repairs it.
        let mut l = sample_ledger();
        l.events[3].payload_digest = digest(b"forged");
        assert!(l.verify().is_err());
        // try_append does not repair; it validates against the (intact) tail and appends normally.
        let _ = l.try_append("admin", "user", "user.created", None, b"u");
        assert!(l.verify().is_err(), "no operation silently re-anchored");
    }

    // --- §2.6 verify_bundle_chain ------------------------------------------------------------

    #[test]
    fn verify_bundle_chain_verifies_an_isolated_good_book_chain() {
        let l = sample_ledger();
        // Export ONLY the book chain's members (as a per-book bundle would).
        let members: Vec<Event> = l.events_in_chain(&book(B1)).into_iter().cloned().collect();
        assert_eq!(members.len(), 2);
        // Independently verifiable WITHOUT the global spine / other chains.
        assert_eq!(Ledger::verify_bundle_chain(&members, &book(B1)), Ok(2));
        assert_eq!(
            Ledger::verify_bundle_chain_verdict(&members, &book(B1)),
            BundleVerdict::Verified { length: 2 }
        );
    }

    #[test]
    fn verify_bundle_chain_flags_a_tampered_bundle() {
        let l = sample_ledger();
        let mut members: Vec<Event> = l.events_in_chain(&book(B1)).into_iter().cloned().collect();
        // Forge the act's content in the bundle (leave its stored hash) ⇒ self-hash mismatch.
        members[1].payload_digest = digest(b"forged-in-transit");
        match Ledger::verify_bundle_chain(&members, &book(B1)) {
            Err(b) => {
                assert_eq!(b.chain, book(B1));
                assert_eq!(b.kind, BreakKind::HashMismatch);
                assert_eq!(b.chain_seq, Some(1));
                assert_eq!(b.event_id, Some(members[1].id));
            }
            Ok(_) => panic!("tampered bundle must not verify"),
        }
        assert!(matches!(
            Ledger::verify_bundle_chain_verdict(&members, &book(B1)),
            BundleVerdict::Broken(_)
        ));
    }

    #[test]
    fn verify_bundle_chain_flags_a_wrong_genesis_bundle() {
        // A bundle whose first book member is not `book.opened` is rejected as a bad genesis.
        let mut l = Ledger::new();
        l.append(
            "sec",
            &format!("book:{B1}/act:{A1}"),
            "act.sealed",
            None,
            b"a",
        );
        let members: Vec<Event> = l.events().to_vec();
        match Ledger::verify_bundle_chain(&members, &book(B1)) {
            Err(b) => assert_eq!(b.kind, BreakKind::ChainGenesisWrong),
            Ok(_) => panic!("wrong-genesis bundle must not verify"),
        }
    }

    // --- preservation: additive types serde round-trip ---------------------------------------

    #[test]
    fn chain_break_and_report_serde_round_trip() {
        let mut l = sample_ledger();
        l.events[2].payload_digest = digest(b"forged");
        let report = l.integrity_report();
        let json = serde_json::to_string(&report).unwrap();
        let back: IntegrityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn chain_status_without_first_break_deserializes_via_default() {
        // Back-compat: a persisted ChainStatus predating `first_break` still loads.
        let legacy = r#"{"chain":"application","genesis_kind":"settings.updated","length":2,"head":null,"verified":true}"#;
        let status: ChainStatus = serde_json::from_str(legacy).unwrap();
        assert!(status.verified);
        assert!(status.first_break.is_none());
    }
}
