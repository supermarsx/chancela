//! Postgres backend integration stubs (wp14 Phase 1).
//!
//! These tests require a live PostgreSQL reachable at `DATABASE_URL` and are therefore
//! `#[ignore]`d by default AND compiled only under the off-by-default `postgres` feature, so the
//! standard `cargo test -p chancela-store` (and the desktop/browser builds) stay Postgres-free and
//! offline. The full backend-agnostic round-trip suite (persist → reload → ledger-replay parity
//! across `{sqlite, postgres}`) runs in the testcontainers lane / compose smoke (plan §8, Phase 3).
//!
//! Run locally against a throwaway database with, e.g.:
//! ```sh
//! DATABASE_URL=postgres://chancela:chancela@localhost:5432/chancela_test \
//!   cargo test -p chancela-store --features postgres -- --ignored
//! ```
#![cfg(feature = "postgres")]

use chancela_ledger::Ledger;
use chancela_store::{Store, StoreBackendSelection};

fn database_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())
}

/// Open the Postgres backend, append one ledger event through the frozen `persist(|tx| …)` closure,
/// and prove the boot `load` replay reconstructs the same single-event chain and verifies clean.
/// This exercises the §4 atomic-append + single-writer write path and the boot replay path.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn persist_and_reload_event_roundtrips_on_postgres() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");

    let mut ledger = Ledger::new();
    let event = ledger
        .append(
            "amelia.marques",
            "application",
            "app.started",
            None,
            b"postgres-roundtrip",
        )
        .clone();
    store
        .persist(|tx| tx.append_event(&event))
        .expect("persist event on postgres");

    let loaded = store.load().expect("reload from postgres");
    assert_eq!(loaded.ledger.len(), 1, "one event should replay");
    assert!(
        loaded.chain_status.is_ok(),
        "replayed chain must verify clean"
    );
}
