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
fn chronology_shareholders_graph_has_deterministic_nodes_edges_and_provenance() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());
    let chrono = Chronology::build(&extract);
    let graph = chrono.graph(&extract).shareholders;

    let node_ids: Vec<&str> = graph.nodes.iter().map(|node| node.id.as_str()).collect();
    assert_eq!(node_ids, vec!["entity", "shareholder-0", "shareholder-1"]);
    assert!(graph.warnings.is_empty(), "unexpected warnings: {graph:?}");

    let rui = &graph.nodes[1];
    assert_eq!(rui.label, "Rui Tavares Nogueira");
    assert_eq!(rui.kind, "person");
    assert_eq!(rui.category.as_deref(), Some("shareholder"));
    assert_eq!(rui.source_inscription.as_deref(), Some("1"));
    assert_eq!(rui.source_date.as_deref(), Some("2020-01-15"));

    let edge_ids: Vec<&str> = graph.edges.iter().map(|edge| edge.id.as_str()).collect();
    assert_eq!(edge_ids, vec!["shareholding-0", "shareholding-1"]);
    let first = &graph.edges[0];
    assert_eq!(first.from, "entity");
    assert_eq!(first.to, "shareholder-0");
    assert_eq!(first.label, "4.500,00 Euros");
    assert_eq!(first.kind, "shareholding");
    assert_eq!(first.source_inscription.as_deref(), Some("1"));
    assert_eq!(first.source_date.as_deref(), Some("2020-01-15"));
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
fn chronology_organs_graph_has_deterministic_nodes_edges_and_provenance() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());
    let chrono = Chronology::build(&extract);
    let graph = chrono.graph(&extract).organs;

    let node_ids: Vec<&str> = graph.nodes.iter().map(|node| node.id.as_str()).collect();
    assert_eq!(node_ids, vec!["entity", "officer-0", "officer-1"]);
    assert!(graph.warnings.is_empty(), "unexpected warnings: {graph:?}");

    let amelia = &graph.nodes[1];
    assert_eq!(amelia.label, "Amélia Marques");
    assert_eq!(amelia.category.as_deref(), Some("officer"));
    assert_eq!(amelia.source_inscription.as_deref(), Some("1"));
    assert_eq!(amelia.source_date.as_deref(), Some("2026-05-11"));

    let bruno = &graph.nodes[2];
    assert_eq!(bruno.label, "Bruno Alves Ferreira");
    assert_eq!(bruno.source_inscription.as_deref(), Some("2"));
    assert_eq!(bruno.source_date.as_deref(), Some("2021-03-05"));

    let designation = graph
        .edges
        .iter()
        .find(|edge| edge.id == "organ-designation-1")
        .expect("Bruno designation edge");
    assert_eq!(designation.from, "entity");
    assert_eq!(designation.to, "officer-1");
    assert_eq!(designation.label, "Gerente");
    assert_eq!(designation.kind, "organ_designation");
    assert_eq!(designation.source_inscription.as_deref(), Some("2"));
    assert_eq!(designation.source_date.as_deref(), Some("2021-03-05"));

    let cessation = graph
        .edges
        .iter()
        .find(|edge| edge.id == "organ-cessation-1")
        .expect("Bruno cessation edge");
    assert_eq!(cessation.from, "entity");
    assert_eq!(cessation.to, "officer-1");
    assert_eq!(cessation.label, "cessation");
    assert_eq!(cessation.kind, "organ_cessation");
    assert_eq!(cessation.source_inscription.as_deref(), Some("3 Av. 1"));
    assert_eq!(cessation.source_date.as_deref(), Some("2023-06-20"));
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
fn chronology_relationships_graph_is_an_honest_empty_stub_without_corporate_relationships() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());
    let chrono = Chronology::build(&extract);
    let graph = chrono.graph(&extract).relationships;

    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.nodes[0].id, "entity");
    assert!(graph.edges.is_empty(), "no fabricated edges: {graph:?}");
    assert!(
        graph
            .warnings
            .iter()
            .any(|warning| warning.contains("No structured corporate relationship evidence")),
        "empty relationship graph explains why it has no edges: {graph:?}"
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
    assert_eq!(a.graph(&extract), b.graph(&extract));
}

// ---- The live consultation page's real layout -------------------------------------------------
//
// These are the four screens the user saw wrong: a single `Other` event described by a postal
// line, an empty sócios graph ("Sem código Mermaid"), no órgão social, and a relations graph with
// no edges. All four were downstream of one parse failure — the act kind of the only inscrição.

#[test]
fn live_layout_chronology_is_a_typed_sourced_constitution() {
    let extract = lookup(MockRegistryTransport::from_fixture_live_spq());
    let chrono = Chronology::build(&extract);

    assert_eq!(chrono.events.len(), 1);
    let e = &chrono.events[0];
    assert_eq!(e.kind, ChronologyKind::Constitution);
    assert_eq!(e.date.as_deref(), Some("2026-05-12"));
    assert_eq!(e.source_inscription, "1");
    assert!(
        e.description.contains("ENCOSTO ESTRATÉGICO"),
        "description was {:?}",
        e.description
    );
    // The description must never be the seat's postal/locality line.
    assert!(!e.description.contains("1250"));
    assert_eq!(
        e.actors,
        vec![
            "RUI TAVARES NOGUEIRA".to_owned(),
            "AMÉLIA MARQUES".to_owned()
        ]
    );
}

#[test]
fn live_layout_shareholders_graph_has_both_socios() {
    let extract = lookup(MockRegistryTransport::from_fixture_live_spq());
    let chrono = Chronology::build(&extract);

    let m = chrono.shareholders_mermaid(&extract);
    assert!(m.starts_with("graph"), "mermaid was {m:?}");
    assert!(m.contains("RUI TAVARES NOGUEIRA"));
    assert!(m.contains("AMÉLIA MARQUES"));

    let graph = chrono.graph(&extract).shareholders;
    assert!(
        graph.warnings.is_empty(),
        "unexpected warnings: {:?}",
        graph.warnings
    );
    // Entity node + two sócios, each linked by a quota edge.
    assert_eq!(graph.nodes.len(), 3);
    assert_eq!(graph.edges.len(), 2);
    assert!(graph.edges.iter().all(|e| e.label.contains("Euros")));
    assert!(
        graph
            .edges
            .iter()
            .all(|e| e.source_inscription.as_deref() == Some("1"))
    );
}

#[test]
fn live_layout_organs_graph_has_the_gerente() {
    let extract = lookup(MockRegistryTransport::from_fixture_live_spq());
    let chrono = Chronology::build(&extract);

    let m = chrono.organs_mermaid(&extract);
    assert!(m.contains("AMÉLIA MARQUES"), "mermaid was {m:?}");

    let graph = chrono.graph(&extract).organs;
    assert!(
        graph
            .nodes
            .iter()
            .any(|n| n.label.contains("AMÉLIA MARQUES")),
        "organ nodes were {:?}",
        graph.nodes
    );
    assert!(!graph.edges.is_empty());
}
