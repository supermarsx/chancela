//! `chancela-ledger` — an append-only, hash-chained event ledger.
//!
//! This crate is the integrity backbone required by the Chancela spec:
//!
//! - **DAT-10** — every meaningful mutation generates a ledger event carrying actor,
//!   justification, timestamp, entity scope, prior event hash, and payload digest.
//! - **DAT-11** — a cryptographic hash chain is maintained so that tampering with either
//!   the *sequence* or the *content* of events is detectable.
//! - **ARC-11/12** — the chain is recomputable and independently verifiable.
//!
//! The implementation is deliberately in-memory (`Vec<Event>`). Persistence and the
//! per-company / per-book / global chain fan-out (DAT-11) are layered on top by callers
//! (`chancela-core` seals acts by appending here; a storage backend can replay `events()`).
//!
//! # Hash preimage layout
//!
//! Each event's `hash` is `sha256` over the concatenation, in this exact order, of:
//!
//! ```text
//! prev_hash              (32 bytes)
//! seq                    ( 8 bytes, big-endian u64)
//! actor                  (UTF-8 bytes)
//! 0x1F                   (unit separator, unambiguous field delimiter)
//! scope                  (UTF-8 bytes)
//! 0x1F
//! kind                   (UTF-8 bytes)
//! 0x1F
//! timestamp              (RFC 3339 UTF-8 bytes)
//! 0x1F
//! payload_digest         (32 bytes)
//! ```
//!
//! The `0x1F` (ASCII unit separator) delimiters between the variable-length string fields
//! prevent a collision where, e.g., `actor = "ab"`, `scope = "c"` would otherwise hash the
//! same preimage as `actor = "a"`, `scope = "bc"`. The fixed-width fields (`prev_hash`,
//! `seq`, `payload_digest`) are unambiguous by width and need no delimiter.
//!
//! The genesis event uses `prev_hash = [0u8; 32]`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Field delimiter used between variable-length string fields in the hash preimage.
const FIELD_SEP: u8 = 0x1F;

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

/// A single, immutable entry in the ledger's hash chain (DAT-10).
///
/// The fields mirror exactly the audit envelope required by the spec: `actor` (who),
/// `justification` (why, optional), `timestamp` (when), `scope` (which entity/book/act the
/// event concerns), `kind` (a caller-defined event type such as `"act.sealed"`),
/// `payload_digest` (the sha256 of the mutation's content), plus the chaining fields
/// `prev_hash` and `hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Random, stable identity for this event.
    pub id: EventId,
    /// Monotonically increasing position in the chain, starting at 0 for genesis.
    pub seq: u64,
    /// The actor responsible for the mutation (user id, service principal, …).
    pub actor: String,
    /// Optional human justification captured at mutation time.
    pub justification: Option<String>,
    /// When the event was recorded (UTC recommended).
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// The entity/book/act scope this event belongs to (DAT-10).
    pub scope: String,
    /// Caller-defined event type, e.g. `"book.opened"`, `"act.sealed"`.
    pub kind: String,
    /// sha256 digest of the mutation payload (the content, kept out of the ledger itself).
    pub payload_digest: [u8; 32],
    /// Hash of the preceding event, or `[0; 32]` for the genesis event.
    pub prev_hash: [u8; 32],
    /// This event's own hash over the preimage documented at crate level.
    pub hash: [u8; 32],
}

impl Event {
    /// Recompute this event's hash from its own fields and a supplied `prev_hash`.
    ///
    /// Used both when appending (to fill in `hash`) and when verifying (to detect any
    /// tampering with the stored fields or the chain linkage).
    fn compute_hash(&self, prev_hash: &[u8; 32]) -> [u8; 32] {
        compute_hash(
            prev_hash,
            self.seq,
            &self.actor,
            &self.scope,
            &self.kind,
            self.timestamp,
            &self.payload_digest,
        )
    }
}

/// Errors surfaced when a chain fails verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// The genesis event did not carry the required all-zero `prev_hash`.
    #[error("genesis event (seq 0) must have an all-zero prev_hash")]
    BadGenesis,
    /// Sequence numbers were not the expected strictly-increasing 0,1,2,… run.
    #[error("sequence broken at index {index}: expected seq {expected}, found {found}")]
    SequenceBroken {
        /// Position in the event vector where the break was detected.
        index: usize,
        /// The `seq` value the chain required at this position.
        expected: u64,
        /// The `seq` value actually found.
        found: u64,
    },
    /// An event's stored `prev_hash` did not match the previous event's `hash`.
    #[error("chain link broken at seq {seq}: prev_hash does not match preceding event")]
    LinkBroken {
        /// The `seq` of the event whose backward link is broken.
        seq: u64,
    },
    /// An event's stored `hash` did not match a recomputation of its own contents.
    #[error("event hash mismatch at seq {seq}: contents were altered after sealing")]
    HashMismatch {
        /// The `seq` of the tampered event.
        seq: u64,
    },
}

/// Compute the sha256 digest of an arbitrary payload (the DAT-10 payload digest).
///
/// Callers digest their mutation content here and pass the result into the ledger, so the
/// ledger records *what changed* without storing the (possibly large or sensitive) content.
pub fn digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().into()
}

/// Compute an event hash from its constituent fields. See the crate-level preimage docs.
#[allow(clippy::too_many_arguments)]
fn compute_hash(
    prev_hash: &[u8; 32],
    seq: u64,
    actor: &str,
    scope: &str,
    kind: &str,
    timestamp: OffsetDateTime,
    payload_digest: &[u8; 32],
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
        .expect("OffsetDateTime always formats as RFC 3339");
    hasher.update(ts.as_bytes());
    hasher.update([FIELD_SEP]);
    hasher.update(payload_digest);
    hasher.finalize().into()
}

/// An append-only, hash-chained ledger of events (DAT-10/11).
///
/// The ledger is write-once from the outside: there is no public API to mutate or remove an
/// existing event. New events may only be appended, and each append links to the prior
/// event's hash. [`Ledger::verify`] recomputes the whole chain to detect any tampering.
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
    /// the events exactly as persisted** — it does *not* re-append or re-hash them, so the
    /// frozen hash preimage and every stored `hash`/`prev_hash`/`timestamp` are preserved
    /// byte-for-byte. A store backend replays its rows (ordered by `seq`) through here to
    /// rebuild the in-memory chain after a restart.
    ///
    /// The adopted chain is then run through the **same** verification as [`Ledger::verify`],
    /// so a tampered or truncated store is detected. Rather than refusing to construct, this
    /// returns the (always-constructed) [`Ledger`] alongside the verification outcome: `Ok(n)`
    /// for a sound chain of `n` events, or the first [`LedgerError`] for a broken one. Callers
    /// (the boot path) surface a broken chain loudly but can still start and inspect it — the
    /// events are in hand regardless of the outcome.
    ///
    /// An empty input yields an empty ledger and `Ok(0)`.
    pub fn try_from_events(events: Vec<Event>) -> (Ledger, Result<u64, LedgerError>) {
        let ledger = Ledger { events };
        let status = ledger.verify();
        (ledger, status)
    }

    /// Append a new event and return a reference to it.
    ///
    /// The new event's `seq` is the current length, its `prev_hash` is the previous event's
    /// `hash` (or `[0; 32]` for genesis), and its `timestamp` is captured as `now` in UTC.
    /// The event's own `hash` is computed over the preimage documented at crate level.
    pub fn append(
        &mut self,
        actor: &str,
        scope: &str,
        kind: &str,
        justification: Option<&str>,
        payload: &[u8],
    ) -> &Event {
        let seq = self.events.len() as u64;
        let prev_hash = self.events.last().map(|e| e.hash).unwrap_or([0u8; 32]);
        let timestamp = OffsetDateTime::now_utc();
        let payload_digest = digest(payload);
        let hash = compute_hash(
            &prev_hash,
            seq,
            actor,
            scope,
            kind,
            timestamp,
            &payload_digest,
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
            hash,
        });
        self.events.last().expect("just pushed an event")
    }

    /// Verify the entire chain.
    ///
    /// On success returns the number of events. On failure returns the first broken link,
    /// with the specific integrity property that was violated:
    ///
    /// - genesis `prev_hash` must be all-zero ([`LedgerError::BadGenesis`]);
    /// - `seq` must be the strictly-increasing run 0,1,2,… ([`LedgerError::SequenceBroken`]);
    /// - each `prev_hash` must equal the preceding event's `hash` ([`LedgerError::LinkBroken`]);
    /// - each `hash` must match a recomputation of that event's own contents
    ///   ([`LedgerError::HashMismatch`]).
    ///
    /// An empty ledger verifies successfully (returns `Ok(0)`).
    pub fn verify(&self) -> Result<u64, LedgerError> {
        let mut prev_hash = [0u8; 32];
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
            if event.prev_hash != prev_hash {
                return Err(LedgerError::LinkBroken { seq: event.seq });
            }
            let recomputed = event.compute_hash(&prev_hash);
            if recomputed != event.hash {
                return Err(LedgerError::HashMismatch { seq: event.seq });
            }
            prev_hash = event.hash;
        }
        Ok(self.events.len() as u64)
    }

    /// Borrow the full event log in append order.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// The hash of the most recent event, i.e. the current chain head (`None` if empty).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ledger_verifies() {
        let ledger = Ledger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.verify(), Ok(0));
        assert_eq!(ledger.head(), None);
    }

    #[test]
    fn genesis_has_zero_prev_hash() {
        let mut ledger = Ledger::new();
        let ev = ledger.append("alice", "book:1", "book.opened", None, b"termo");
        assert_eq!(ev.seq, 0);
        assert_eq!(ev.prev_hash, [0u8; 32]);
        assert_ne!(ev.hash, [0u8; 32]);
    }

    #[test]
    fn append_chain_links_and_verifies() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", Some("annual"), b"a");
        ledger.append("bob", "book:1", "act.sealed", None, b"b");
        ledger.append("carol", "book:1", "act.sealed", None, b"c");

        assert_eq!(ledger.len(), 3);
        assert_eq!(ledger.verify(), Ok(3));

        // Each event links backward to the previous event's hash.
        let events = ledger.events();
        for w in events.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].hash);
        }
        assert_eq!(ledger.head(), Some(events[2].hash));
    }

    #[test]
    fn payload_digest_matches_free_function() {
        let mut ledger = Ledger::new();
        let ev = ledger.append("alice", "book:1", "act.sealed", None, b"deliberations");
        assert_eq!(ev.payload_digest, digest(b"deliberations"));
    }

    #[test]
    fn tamper_with_payload_digest_is_detected() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", None, b"a");
        ledger.append("bob", "book:1", "act.sealed", None, b"b");
        assert_eq!(ledger.verify(), Ok(2));

        // Simulate an attacker rewriting the content digest of a sealed event without
        // recomputing the (chained) hash — verification must catch the hash mismatch.
        ledger.events[1].payload_digest = digest(b"forged");
        assert_eq!(ledger.verify(), Err(LedgerError::HashMismatch { seq: 1 }));
    }

    #[test]
    fn tamper_with_actor_is_detected() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", None, b"a");
        ledger.append("bob", "book:1", "act.sealed", None, b"b");

        ledger.events[0].actor = "mallory".to_owned();
        // Rewriting genesis contents breaks its own hash first.
        assert_eq!(ledger.verify(), Err(LedgerError::HashMismatch { seq: 0 }));
    }

    #[test]
    fn tamper_with_order_is_detected() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "e0", None, b"a");
        ledger.append("bob", "book:1", "e1", None, b"b");
        ledger.append("carol", "book:1", "e2", None, b"c");
        assert_eq!(ledger.verify(), Ok(3));

        // Reorder two events: their seq numbers now no longer match their positions.
        ledger.events.swap(1, 2);
        match ledger.verify() {
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
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "e0", None, b"a");
        ledger.append("bob", "book:1", "e1", None, b"b");
        ledger.append("carol", "book:1", "e2", None, b"c");

        // Remove the middle event: seq 0,2 — the sequence run is broken at index 1.
        ledger.events.remove(1);
        assert_eq!(
            ledger.verify(),
            Err(LedgerError::SequenceBroken {
                index: 1,
                expected: 1,
                found: 2,
            })
        );
    }

    #[test]
    fn forged_genesis_prev_hash_is_detected() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", None, b"a");
        // Give genesis a non-zero prev_hash but keep its self-hash consistent, so the only
        // violated invariant is the genesis rule itself.
        let forged_prev = [7u8; 32];
        ledger.events[0].prev_hash = forged_prev;
        ledger.events[0].hash = ledger.events[0].compute_hash(&forged_prev);
        assert_eq!(ledger.verify(), Err(LedgerError::BadGenesis));
    }

    #[test]
    fn broken_backward_link_is_detected() {
        // A non-genesis event whose stored `prev_hash` no longer matches the preceding event's
        // `hash` — but whose own contents are otherwise untouched — must surface as `LinkBroken`,
        // the chain-linkage violation, and it is checked before the self-hash recomputation.
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", None, b"a");
        ledger.append("bob", "book:1", "act.sealed", None, b"b");
        assert_eq!(ledger.verify(), Ok(2));

        // Repoint seq-1's backward link at a hash that is not the genesis hash. Its own `hash`
        // field is left as-is, so the linkage check (not the hash check) is what fires.
        ledger.events[1].prev_hash = [0xAB; 32];
        assert_eq!(ledger.verify(), Err(LedgerError::LinkBroken { seq: 1 }));
    }

    #[test]
    fn event_serde_round_trips() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", Some("why"), b"a");
        let json = serde_json::to_string(&ledger.events()[0]).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ledger.events()[0]);
    }

    #[test]
    fn whole_ledger_serde_round_trips_and_reverifies() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", None, b"a");
        ledger.append("bob", "book:1", "act.sealed", None, b"b");
        let json = serde_json::to_string(&ledger).unwrap();
        let back: Ledger = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verify(), Ok(2));
        assert_eq!(back.events(), ledger.events());
    }

    #[test]
    fn try_from_events_empty_yields_empty_ledger() {
        let (ledger, status) = Ledger::try_from_events(Vec::new());
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert_eq!(ledger.head(), None);
        assert_eq!(status, Ok(0));
    }

    #[test]
    fn try_from_events_round_trips_through_serialization() {
        // Build a chain, persist its events (serialize), then reconstruct via the boot path.
        let mut original = Ledger::new();
        original.append("alice", "book:1", "book.opened", Some("annual"), b"a");
        original.append("bob", "book:1", "act.sealed", None, b"b");
        original.append("carol", "book:1", "act.sealed", Some("why"), b"c");

        let json = serde_json::to_string(original.events()).unwrap();
        let persisted: Vec<Event> = serde_json::from_str(&json).unwrap();

        let (ledger, status) = Ledger::try_from_events(persisted);
        // Verification passes and the reconstructed chain is identical to the original.
        assert_eq!(status, Ok(3));
        assert_eq!(ledger.verify(), Ok(3));
        assert_eq!(ledger.len(), original.len());
        assert_eq!(ledger.head(), original.head());
        assert_eq!(ledger.events(), original.events());
    }

    #[test]
    fn try_from_events_adopts_hashes_without_re_hashing() {
        // The reconstructed events must be byte-identical to what was persisted: no fresh
        // timestamp, no recomputed hash. Adopting, not re-appending, is the whole point.
        let mut original = Ledger::new();
        original.append("alice", "book:1", "book.opened", None, b"a");
        let persisted = original.events().to_vec();

        let (ledger, status) = Ledger::try_from_events(persisted.clone());
        assert_eq!(status, Ok(1));
        assert_eq!(ledger.events(), persisted.as_slice());
    }

    #[test]
    fn try_from_events_rejects_hash_mismatch() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", None, b"a");
        ledger.append("bob", "book:1", "act.sealed", None, b"b");
        let mut events = ledger.events().to_vec();

        // Tamper with content but leave the stored hash stale.
        events[1].payload_digest = digest(b"forged");
        let (rebuilt, status) = Ledger::try_from_events(events);
        assert_eq!(status, Err(LedgerError::HashMismatch { seq: 1 }));
        // The ledger is still constructed so the boot path can inspect it.
        assert_eq!(rebuilt.len(), 2);
    }

    #[test]
    fn try_from_events_rejects_bad_genesis() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", None, b"a");
        let mut events = ledger.events().to_vec();

        // Forge a non-zero genesis prev_hash but keep its self-hash consistent, so the only
        // violated invariant is the genesis rule itself.
        let forged_prev = [7u8; 32];
        events[0].prev_hash = forged_prev;
        events[0].hash = events[0].compute_hash(&forged_prev);
        let (_, status) = Ledger::try_from_events(events);
        assert_eq!(status, Err(LedgerError::BadGenesis));
    }

    #[test]
    fn try_from_events_rejects_broken_sequence() {
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "e0", None, b"a");
        ledger.append("bob", "book:1", "e1", None, b"b");
        ledger.append("carol", "book:1", "e2", None, b"c");
        let mut events = ledger.events().to_vec();

        // Drop the middle event: seq run becomes 0,2 — broken at index 1.
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
        let mut ledger = Ledger::new();
        ledger.append("alice", "book:1", "book.opened", None, b"a");
        ledger.append("bob", "book:1", "act.sealed", None, b"b");
        let mut events = ledger.events().to_vec();

        // Repoint seq-1's backward link at a hash that is not genesis's, leaving its own hash
        // untouched, so the linkage check (not the self-hash check) is what fires.
        events[1].prev_hash = [0xAB; 32];
        let (_, status) = Ledger::try_from_events(events);
        assert_eq!(status, Err(LedgerError::LinkBroken { seq: 1 }));
    }
}
