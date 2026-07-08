//! Chronology / relationship-graph tests (DOC-30/31/32) over the shipped certidão fixtures.
//!
//! Builds a [`Chronology`] from each parsed fixture extract and asserts: ordered typed events,
//! correct kinds, DOC-32 provenance on *every* event, and structurally valid Mermaid output.

use chancela_registry::chronology::{Chronology, ChronologyKind};
use chancela_registry::{AccessCode, MockRegistryTransport, RegistryClient, RegistryExtract};

const TEST_CODE: &str = "7110-6727-7477";

fn lookup(transport: MockRegistryTransport) -> RegistryExtract {
    let code = AccessCode::parse(TEST_CODE).expect("valid code");
    RegistryClient::new(transport)
        .lookup(&code, None)
        .expect("lookup succeeds")
}

#[test]
fn spq_chronology_is_ordered_typed_and_fully_sourced() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());
    let chrono = Chronology::build(&extract);

    // One event per inscrição here (the SPQ amendment touches only the seat → a single SeatChange).
    let kinds: Vec<ChronologyKind> = chrono.events.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            ChronologyKind::Constitution,
            ChronologyKind::Designation,
            ChronologyKind::Cessation,
            ChronologyKind::SeatChange,
        ]
    );

    // DOC-32: every event traces to a non-empty inscrição reference, in the certidão's printed order.
    let sources: Vec<&str> = chrono
        .events
        .iter()
        .map(|e| e.source_inscription.as_str())
        .collect();
    assert_eq!(sources, vec!["1", "2", "3 Av. 1", "4"]);
    assert!(
        chrono
            .events
            .iter()
            .all(|e| !e.source_inscription.is_empty()),
        "every event carries provenance"
    );

    // The constitution event carries its date and its named parties (sócios + gerente).
    let constitution = &chrono.events[0];
    assert_eq!(constitution.date.as_deref(), Some("2020-01-15"));
    assert!(constitution.description.contains("Constituição"));
    assert!(
        constitution
            .actors
            .iter()
            .any(|a| a.contains("Rui Tavares")),
        "sócio surfaced as an actor: {:?}",
        constitution.actors
    );

    // The cessation names who ceased.
    let cessation = &chrono.events[2];
    assert_eq!(cessation.kind, ChronologyKind::Cessation);
    assert!(
        cessation.actors.iter().any(|a| a.contains("Bruno Alves")),
        "ceased member surfaced: {:?}",
        cessation.actors
    );

    // The seat amendment renders the new sede in its description.
    assert!(chrono.events[3].description.contains("sede"));
}

#[test]
fn sa_amendment_is_a_capital_change() {
    let extract = lookup(MockRegistryTransport::from_fixture_sa());
    let chrono = Chronology::build(&extract);

    assert_eq!(
        chrono.events.first().map(|e| e.kind),
        Some(ChronologyKind::Constitution)
    );
    assert!(
        chrono
            .events
            .iter()
            .any(|e| e.kind == ChronologyKind::CapitalChange),
        "the SA fixture's ALTERAÇÕES ... CAPITAL yields a CapitalChange: {:?}",
        chrono.events.iter().map(|e| e.kind).collect::<Vec<_>>()
    );
    // Designation of the two-member conselho present.
    assert!(
        chrono
            .events
            .iter()
            .any(|e| e.kind == ChronologyKind::Designation)
    );
    assert!(
        chrono
            .events
            .iter()
            .all(|e| !e.source_inscription.is_empty())
    );
}

#[test]
fn fundacao_chronology_tracks_organ_lifecycle() {
    let extract = lookup(MockRegistryTransport::from_fixture_fundacao());
    let chrono = Chronology::build(&extract);

    assert!(!chrono.events.is_empty());
    assert!(
        chrono
            .events
            .iter()
            .any(|e| e.kind == ChronologyKind::Designation)
    );
    assert!(
        chrono
            .events
            .iter()
            .any(|e| e.kind == ChronologyKind::Cessation)
    );
    assert!(
        chrono
            .events
            .iter()
            .all(|e| !e.source_inscription.is_empty())
    );
}

#[test]
fn shareholders_mermaid_is_a_graph_with_socio_nodes() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());
    let chrono = Chronology::build(&extract);
    let m = chrono.shareholders_mermaid(&extract);

    assert!(m.starts_with("graph"), "starts with graph: {m}");
    assert!(m.contains("entity[\""), "has the entity node");
    // The two founding sócios of the SPQ constitution are nodes with quota edges.
    assert!(m.contains("s0[\""));
    assert!(m.contains("s1[\""));
    assert!(m.contains("entity -->|\""), "quota edges present");
    assert!(m.contains("Rui Tavares Nogueira"));
}

#[test]
fn organs_mermaid_is_a_timeline_ordered_by_date() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());
    let chrono = Chronology::build(&extract);
    let m = chrono.organs_mermaid(&extract);

    assert!(m.starts_with("timeline"), "starts with timeline: {m}");
    assert!(m.contains("title Órgãos sociais"));
    // Designations and a cessation surface as dated timeline rows.
    assert!(m.contains("Designação"));
    assert!(m.contains("Cessação"));

    // The ISO date rows are emitted in ascending order (deterministic, no clock).
    let dates: Vec<&str> = m
        .lines()
        .filter_map(|l| l.trim().split(" : ").next())
        .filter(|d| d.len() == 10 && d.as_bytes()[4] == b'-')
        .collect();
    let mut sorted = dates.clone();
    sorted.sort_unstable();
    assert_eq!(dates, sorted, "timeline rows are chronological: {dates:?}");
}

#[test]
fn relationships_mermaid_is_a_valid_graph_stub() {
    // The SPQ sócios are natural persons → an honest single-node stub, still a valid graph.
    let extract = lookup(MockRegistryTransport::from_fixture_spq());
    let chrono = Chronology::build(&extract);
    let m = chrono.relationships_mermaid(&extract);

    assert!(m.starts_with("graph"), "starts with graph: {m}");
    assert!(m.contains("self[\""), "entity node present");
    // No corporate sócio in this fixture → no relation edges fabricated.
    assert!(
        !m.contains("self ---"),
        "no invented inter-company edge: {m}"
    );
}

#[test]
fn chronology_is_deterministic() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());
    let a = Chronology::build(&extract);
    let b = Chronology::build(&extract);
    assert_eq!(a, b);
    assert_eq!(
        a.shareholders_mermaid(&extract),
        b.shareholders_mermaid(&extract)
    );
    assert_eq!(a.organs_mermaid(&extract), b.organs_mermaid(&extract));
}
