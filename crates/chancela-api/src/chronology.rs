//! Chronology / relationship-graph endpoint (spec DOC-30/31/32) — a native, **explainable** graph
//! feature over a stored [`RegistryExtract`].
//!
//! `GET /v1/entities/{id}/chronology` builds the normalized event timeline (DOC-30), the Mermaid
//! diagram set (DOC-31), and structured graph data from the entity's imported certidão extract and
//! returns them as thin wire views (house convention). Every event carries its `source_inscription`
//! (DOC-32 provenance).
//! `404` when the entity is unknown or nothing has been imported. Requires a valid session, exactly
//! like its sibling `GET /v1/entities/{id}/registry` (both read the same stored extract).

use axum::Json;
use axum::extract::{Path, State};
use chancela_core::{Act, ActState, Book, BookId, EntityId};
use chancela_registry::RegistryExtract;
use chancela_registry::chronology::{
    Chronology, ChronologyEvent, ChronologyGraph, ChronologyGraphBundle, ChronologyKind,
};
use serde::Serialize;
use uuid::Uuid;

use chancela_authz::Permission;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::{require_permission, scope_of_entity};
use crate::dto::format_date;
use crate::error::ApiError;
use std::collections::{BTreeMap, HashMap};

/// Wire view of one normalized timeline event. `kind` is the bare [`ChronologyKind`] variant name
/// (`"Constitution"`, `"CapitalChange"`, …).
#[derive(Serialize)]
pub struct ChronologyEventView {
    pub date: Option<String>,
    pub kind: String,
    pub description: String,
    /// The registry entry this event traces to — never empty (DOC-32 provenance).
    pub source_inscription: String,
    pub actors: Vec<String>,
}

impl From<&ChronologyEvent> for ChronologyEventView {
    fn from(e: &ChronologyEvent) -> Self {
        ChronologyEventView {
            date: e.date.clone(),
            kind: kind_name(e.kind).to_owned(),
            description: e.description.clone(),
            source_inscription: e.source_inscription.clone(),
            actors: e.actors.clone(),
        }
    }
}

/// The three DOC-31 Mermaid diagram strings for an entity.
#[derive(Serialize)]
pub struct MermaidBundleView {
    /// Shareholders/quotas `graph` (sócios → quotas).
    pub shareholders: String,
    /// Órgãos/management `timeline` (designations + cessations over time).
    pub organs: String,
    /// Inter-company relationship `graph` stub.
    pub relationships: String,
}

#[derive(Serialize)]
pub struct ChronologyEventKindCountView {
    pub kind: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct ChronologyGraphCountView {
    pub nodes: usize,
    pub edges: usize,
    pub warnings: usize,
}

#[derive(Serialize)]
pub struct ChronologyGraphAnalyticsView {
    pub shareholders: ChronologyGraphCountView,
    pub organs: ChronologyGraphCountView,
    pub relationships: ChronologyGraphCountView,
}

#[derive(Serialize)]
pub struct ChronologyAnalyticsView {
    pub total_events: usize,
    pub dated_events: usize,
    pub undated_events: usize,
    pub event_kinds: Vec<ChronologyEventKindCountView>,
    pub source_inscription_count: usize,
    pub source_inscriptions: Vec<String>,
    pub graph: ChronologyGraphAnalyticsView,
}

impl ChronologyAnalyticsView {
    fn build(events: &[ChronologyEventView], graph: &ChronologyGraphBundle) -> Self {
        let mut kind_counts = BTreeMap::<&str, usize>::new();
        let mut source_inscriptions = Vec::<String>::new();
        for event in events {
            *kind_counts.entry(event.kind.as_str()).or_default() += 1;
            if !source_inscriptions.contains(&event.source_inscription) {
                source_inscriptions.push(event.source_inscription.clone());
            }
        }

        ChronologyAnalyticsView {
            total_events: events.len(),
            dated_events: events.iter().filter(|event| event.date.is_some()).count(),
            undated_events: events.iter().filter(|event| event.date.is_none()).count(),
            event_kinds: kind_counts
                .into_iter()
                .map(|(kind, count)| ChronologyEventKindCountView {
                    kind: kind.to_owned(),
                    count,
                })
                .collect(),
            source_inscription_count: source_inscriptions.len(),
            source_inscriptions,
            graph: ChronologyGraphAnalyticsView {
                shareholders: graph_counts(&graph.shareholders),
                organs: graph_counts(&graph.organs),
                relationships: graph_counts(&graph.relationships),
            },
        }
    }
}

fn graph_counts(
    graph: &chancela_registry::chronology::ChronologyGraph,
) -> ChronologyGraphCountView {
    ChronologyGraphCountView {
        nodes: graph.nodes.len(),
        edges: graph.edges.len(),
        warnings: graph.warnings.len(),
    }
}

#[derive(Clone, Serialize)]
pub struct SealedActSourceView {
    pub kind: &'static str,
    pub act_id: String,
    pub book_id: String,
    pub ata_number: Option<u64>,
    pub payload_digest: Option<String>,
    pub seal_event_seq: Option<u64>,
}

#[derive(Serialize)]
pub struct SealedActProjectionEventView {
    pub date: Option<String>,
    pub kind: String,
    pub description: String,
    pub act_id: String,
    pub book_id: String,
    pub ata_number: Option<u64>,
    pub act_state: String,
    pub source: SealedActSourceView,
}

#[derive(Serialize)]
pub struct SealedActProjectionGraphNodeView {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub source: SealedActSourceView,
}

#[derive(Serialize)]
pub struct SealedActProjectionGraphEdgeView {
    pub id: String,
    pub from: String,
    pub to: String,
    pub label: String,
    pub kind: String,
    pub source: SealedActSourceView,
}

#[derive(Serialize)]
pub struct SealedActProjectionGraphView {
    pub nodes: Vec<SealedActProjectionGraphNodeView>,
    pub edges: Vec<SealedActProjectionGraphEdgeView>,
}

#[derive(Serialize)]
pub struct SealedActProjectionView {
    pub events: Vec<SealedActProjectionEventView>,
    pub graph: SealedActProjectionGraphView,
    pub provenance: Vec<SealedActSourceView>,
    pub legal_validity_claimed: bool,
    pub authority_certified_claimed: bool,
}

/// The chronology response: the ordered event timeline plus Mermaid, structured graph views, and
/// deterministic local analytics over those already-derived technical views.
#[derive(Serialize)]
pub struct ChronologyView {
    pub events: Vec<ChronologyEventView>,
    pub mermaid: MermaidBundleView,
    pub graph: ChronologyGraphBundle,
    pub analytics: ChronologyAnalyticsView,
    pub sealed_act_projection: Option<SealedActProjectionView>,
}

impl ChronologyView {
    /// Build the full view from an extract (DOC-30 events + DOC-31 Mermaid).
    pub fn build(extract: &RegistryExtract) -> Self {
        Self::build_with_projection(Some(extract), None)
    }

    fn build_with_projection(
        extract: Option<&RegistryExtract>,
        sealed_act_projection: Option<SealedActProjectionView>,
    ) -> Self {
        let Some(extract) = extract else {
            let graph = empty_graph_bundle();
            let events = Vec::new();
            let analytics = ChronologyAnalyticsView::build(&events, &graph);
            return ChronologyView {
                events,
                mermaid: MermaidBundleView {
                    shareholders: String::new(),
                    organs: String::new(),
                    relationships: String::new(),
                },
                graph,
                analytics,
                sealed_act_projection,
            };
        };
        let chrono = Chronology::build(extract);
        let events: Vec<ChronologyEventView> = chrono
            .events
            .iter()
            .map(ChronologyEventView::from)
            .collect();
        let mermaid = MermaidBundleView {
            shareholders: chrono.shareholders_mermaid(extract),
            organs: chrono.organs_mermaid(extract),
            relationships: chrono.relationships_mermaid(extract),
        };
        let graph = chrono.graph(extract);
        let analytics = ChronologyAnalyticsView::build(&events, &graph);
        ChronologyView {
            events,
            mermaid,
            graph,
            analytics,
            sealed_act_projection,
        }
    }
}

fn empty_graph_bundle() -> ChronologyGraphBundle {
    ChronologyGraphBundle {
        shareholders: empty_graph(),
        organs: empty_graph(),
        relationships: empty_graph(),
    }
}

fn empty_graph() -> ChronologyGraph {
    ChronologyGraph {
        nodes: Vec::new(),
        edges: Vec::new(),
        warnings: Vec::new(),
    }
}

fn build_sealed_act_projection(
    entity_id: EntityId,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<chancela_core::ActId, Act>,
) -> Option<SealedActProjectionView> {
    let mut owned_books: Vec<_> = books
        .values()
        .filter(|book| book.entity_id == entity_id)
        .map(|book| book.id)
        .collect();
    owned_books.sort_by_key(|book_id| book_id.to_string());

    let mut projected_acts: Vec<&Act> = acts
        .values()
        .filter(|act| {
            owned_books.contains(&act.book_id)
                && matches!(act.state, ActState::Sealed | ActState::Archived)
        })
        .collect();
    projected_acts.sort_by(|left, right| {
        act_sort_key(left)
            .cmp(&act_sort_key(right))
            .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
    });

    if projected_acts.is_empty() {
        return None;
    }

    let projected_ids: Vec<_> = projected_acts.iter().map(|act| act.id).collect();
    let mut events = Vec::new();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut provenance = Vec::new();

    for act in &projected_acts {
        let source = sealed_act_source(act);
        provenance.push(source.clone());
        events.push(SealedActProjectionEventView {
            date: act.meeting_date.map(format_date),
            kind: "SealedAct".to_owned(),
            description: format!(
                "{} ata{}{}",
                state_name(act.state),
                act.ata_number
                    .map(|number| format!(" n.º {number}"))
                    .unwrap_or_default(),
                if act.title.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", act.title.trim())
                }
            ),
            act_id: act.id.to_string(),
            book_id: act.book_id.to_string(),
            ata_number: act.ata_number,
            act_state: state_name(act.state).to_owned(),
            source: source.clone(),
        });
        nodes.push(SealedActProjectionGraphNodeView {
            id: act_node_id(act.id),
            label: act_node_label(act),
            kind: "sealed_act".to_owned(),
            source: source.clone(),
        });

        if let Some(retified_id) = act.retifies {
            events.push(SealedActProjectionEventView {
                date: act.meeting_date.map(format_date),
                kind: "Correction".to_owned(),
                description: format!(
                    "Ata{} rectifies act {}",
                    act.ata_number
                        .map(|number| format!(" n.º {number}"))
                        .unwrap_or_default(),
                    retified_id
                ),
                act_id: act.id.to_string(),
                book_id: act.book_id.to_string(),
                ata_number: act.ata_number,
                act_state: state_name(act.state).to_owned(),
                source: source.clone(),
            });
            edges.push(SealedActProjectionGraphEdgeView {
                id: format!("correction:{}:{}", act.id, retified_id),
                from: act_node_id(act.id),
                to: act_node_id(retified_id),
                label: "retifies".to_owned(),
                kind: "correction".to_owned(),
                source,
            });
        }
    }

    for window in projected_acts.windows(2) {
        let [previous, current] = window else {
            continue;
        };
        if previous.book_id != current.book_id {
            continue;
        }
        if !projected_ids.contains(&previous.id) || !projected_ids.contains(&current.id) {
            continue;
        }
        edges.push(SealedActProjectionGraphEdgeView {
            id: format!("book-sequence:{}:{}", previous.id, current.id),
            from: act_node_id(previous.id),
            to: act_node_id(current.id),
            label: "same book sequence".to_owned(),
            kind: "book_sequence".to_owned(),
            source: sealed_act_source(current),
        });
    }

    Some(SealedActProjectionView {
        events,
        graph: SealedActProjectionGraphView { nodes, edges },
        provenance,
        legal_validity_claimed: false,
        authority_certified_claimed: false,
    })
}

fn act_sort_key(act: &Act) -> (Option<String>, Option<u64>, String, String) {
    (
        act.meeting_date.map(format_date),
        act.ata_number,
        act.book_id.to_string(),
        act.id.to_string(),
    )
}

fn sealed_act_source(act: &Act) -> SealedActSourceView {
    SealedActSourceView {
        kind: "sealed_act",
        act_id: act.id.to_string(),
        book_id: act.book_id.to_string(),
        ata_number: act.ata_number,
        payload_digest: act.payload_digest.map(|digest| crate::hex::hex(&digest)),
        seal_event_seq: act.seal_event_seq,
    }
}

fn act_node_id(act_id: chancela_core::ActId) -> String {
    format!("act:{act_id}")
}

fn act_node_label(act: &Act) -> String {
    act.ata_number
        .map(|number| format!("Ata n.º {number}"))
        .unwrap_or_else(|| format!("Act {}", act.id))
}

fn state_name(state: ActState) -> &'static str {
    match state {
        ActState::Draft => "Draft",
        ActState::Review => "Review",
        ActState::Convened => "Convened",
        ActState::Deliberated => "Deliberated",
        ActState::TextApproved => "TextApproved",
        ActState::Signing => "Signing",
        ActState::Sealed => "Sealed",
        ActState::Archived => "Archived",
    }
}

/// The contract's [`ChronologyKind`] encoding: the bare variant name.
fn kind_name(kind: ChronologyKind) -> &'static str {
    match kind {
        ChronologyKind::Constitution => "Constitution",
        ChronologyKind::Designation => "Designation",
        ChronologyKind::Cessation => "Cessation",
        ChronologyKind::CapitalChange => "CapitalChange",
        ChronologyKind::SeatChange => "SeatChange",
        ChronologyKind::ObjectChange => "ObjectChange",
        ChronologyKind::QuotaTransfer => "QuotaTransfer",
        ChronologyKind::Dissolution => "Dissolution",
        ChronologyKind::Other => "Other",
        // `ChronologyKind` is `#[non_exhaustive]`; any future variant serializes as "Other" until
        // this map is extended, rather than failing the request.
        _ => "Other",
    }
}

/// `GET /v1/entities/{id}/chronology` — the normalized chronology + Mermaid diagrams built from the
/// entity's stored registry extract, or `404` if the entity is unknown or nothing was imported.
pub async fn get_entity_chronology(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<ChronologyView>, ApiError> {
    require_permission(
        &state,
        &actor,
        Permission::EntityRead,
        scope_of_entity(EntityId(id)),
    )
    .await?;
    let entity_id = EntityId(id);
    let entities = state.entities.read().await;
    let entity_exists = entities.contains_key(&entity_id);
    let books = state.books.read().await;
    let acts = state.acts.read().await;
    let extracts = state.registry_extracts.read().await;
    let extract = extracts.get(&entity_id);
    let sealed_act_projection = build_sealed_act_projection(entity_id, &books, &acts);
    if !entity_exists && extract.is_none() && sealed_act_projection.is_none() {
        return Err(ApiError::NotFound);
    }
    if extract.is_none() && sealed_act_projection.is_none() {
        return Err(ApiError::NotFound);
    }
    let view = match (extract, sealed_act_projection) {
        (Some(extract), None) => ChronologyView::build(extract),
        (extract, sealed_act_projection) => {
            ChronologyView::build_with_projection(extract, sealed_act_projection)
        }
    };
    Ok(Json(view))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::SESSION_TTL_SECS;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chancela_core::{
        ActId, ActState, BookId, BookKind, Entity, EntityKind, MeetingChannel, Nipc,
    };
    use serde_json::Value;
    use std::sync::Arc;
    use time::macros::date;
    use tower::ServiceExt;

    /// A structurally faithful certidão with a constitution + a designation inscrição, so the built
    /// chronology has typed events and non-trivial Mermaid.
    fn certidao_html() -> String {
        "<!DOCTYPE html><html lang=\"pt-PT\"><body><div class=\"matricula\">\
         <p>MATRÍCULA</p><table>\
         <tr><td>Matrícula:</td><td>99999/20200101</td></tr>\
         <tr><td>NIF/NIPC:</td><td>503004642</td></tr>\
         <tr><td>Firma:</td><td>Encosto Estratégico, Lda</td></tr>\
         <tr><td>Natureza Jurídica:</td><td>Sociedade por quotas</td></tr>\
         <tr><td>Sede:</td><td>Lisboa</td></tr>\
         </table></div>\
         <div class=\"inscricoes\"><p>Inscrições - Averbamentos - Anotações</p>\
         <div><p>Insc. 1 AP. 1/20200101</p><p>CONSTITUIÇÃO DE SOCIEDADE</p></div>\
         <div><p>Insc. 2 AP. 2/20210305</p><p>DESIGNAÇÃO DE MEMBRO(S) DE ORGÃO(S) SOCIAL(AIS)</p></div>\
         </div></body></html>"
            .to_owned()
    }

    fn state_with(html: String) -> AppState {
        AppState {
            registry: Some(Arc::new(
                chancela_registry::MockRegistryTransport::empty().with_html(html),
            )),
            ..Default::default()
        }
    }

    async fn auth_token(state: &AppState) -> String {
        use crate::users::{User, UserId};
        use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
        use time::format_description::well_known::Rfc3339;
        // RBAC (t64-E3): seed the catalog + make the test actor Owner\@Global so gated endpoints pass.
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(uuid::Uuid::new_v4());
        let user = User {
            id: uid,
            username: "test.actor".to_owned(),
            display_name: "Test Actor".to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            language: Default::default(),
        };
        state.users.write().await.insert(uid, user);
        let token = uuid::Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(SESSION_TTL_SECS),
            },
        );
        token
    }

    async fn send(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
        let token = auth_token(&state).await;
        let mut req = req;
        req.headers_mut()
            .insert("x-chancela-session", token.parse().unwrap());
        let response = crate::router(state)
            .oneshot(req)
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("body is JSON")
        };
        (status, value)
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    fn entity() -> Entity {
        Entity::new(
            "Encosto Estratégico, Lda",
            Nipc::parse("503004642").expect("valid NIPC"),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn projected_act(
        id: u128,
        book_id: BookId,
        title: &str,
        state: ActState,
        ata_number: Option<u64>,
        meeting_date: Option<time::Date>,
        digest_byte: u8,
        seal_event_seq: Option<u64>,
    ) -> Act {
        let mut act = Act::draft(book_id, title, MeetingChannel::Physical);
        act.id = ActId(Uuid::from_u128(id));
        act.state = state;
        act.ata_number = ata_number;
        act.meeting_date = meeting_date;
        act.payload_digest = Some([digest_byte; 32]);
        act.seal_event_seq = seal_event_seq;
        act
    }

    fn post_json(uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    #[tokio::test]
    async fn chronology_is_404_before_import_and_200_with_shape_after() {
        let state = state_with(certidao_html());

        // Create an entity from the registry (stores the extract).
        let (status, report) = send(
            state.clone(),
            post_json(
                "/v1/entities/import-from-registry",
                serde_json::json!({ "code": "1234-5678-9012" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = report["entity"]["id"].as_str().expect("id").to_owned();

        // 200 with the frozen shape.
        let (status, view) =
            send(state.clone(), get(&format!("/v1/entities/{id}/chronology"))).await;
        assert_eq!(status, StatusCode::OK);

        let events = view["events"].as_array().expect("events array");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["kind"], "Constitution");
        assert_eq!(events[1]["kind"], "Designation");
        // DOC-32: every event carries a non-empty source_inscription.
        assert!(
            events
                .iter()
                .all(|e| !e["source_inscription"].as_str().unwrap_or("").is_empty()),
            "every event traces to a source inscrição"
        );
        assert_eq!(events[0]["source_inscription"], "1");

        // DOC-31: the three Mermaid strings are present and structurally valid.
        let mermaid = &view["mermaid"];
        assert!(
            mermaid["shareholders"]
                .as_str()
                .expect("shareholders")
                .starts_with("graph")
        );
        assert!(
            mermaid["organs"]
                .as_str()
                .expect("organs")
                .starts_with("timeline")
        );
        assert!(
            mermaid["relationships"]
                .as_str()
                .expect("relationships")
                .starts_with("graph")
        );

        // Structured graph bundle mirrors the Mermaid views without replacing them.
        let graph = &view["graph"];
        for key in ["shareholders", "organs", "relationships"] {
            assert!(
                graph[key]["nodes"].is_array(),
                "{key} graph exposes nodes: {graph:?}"
            );
            assert!(
                graph[key]["edges"].is_array(),
                "{key} graph exposes edges: {graph:?}"
            );
            assert!(
                graph[key]["warnings"].is_array(),
                "{key} graph exposes warnings: {graph:?}"
            );
        }
        assert_eq!(graph["shareholders"]["nodes"][0]["id"], "entity");
        assert_eq!(graph["relationships"]["nodes"][0]["id"], "entity");
        assert!(
            graph["relationships"]["warnings"]
                .as_array()
                .expect("relationship warnings")
                .iter()
                .any(|warning| warning
                    .as_str()
                    .unwrap_or("")
                    .contains("No structured corporate relationship evidence")),
            "relationship empty-state warning is exposed: {graph:?}"
        );

        // Additive analytics are deterministic counts over the same stored extract and graph only:
        // no registry certification, DRE verification, legal priority, or authority-approved graph.
        let analytics = &view["analytics"];
        assert_eq!(analytics["total_events"], 2);
        assert_eq!(analytics["dated_events"], 2);
        assert_eq!(analytics["undated_events"], 0);
        assert_eq!(analytics["source_inscription_count"], 2);
        assert_eq!(
            analytics["source_inscriptions"],
            serde_json::json!(["1", "2"])
        );
        assert!(
            analytics["event_kinds"]
                .as_array()
                .expect("event kind counts")
                .iter()
                .any(|row| row["kind"] == "Constitution" && row["count"] == 1),
            "constitution kind count is exposed: {analytics:?}"
        );
        assert!(
            analytics["event_kinds"]
                .as_array()
                .expect("event kind counts")
                .iter()
                .any(|row| row["kind"] == "Designation" && row["count"] == 1),
            "designation kind count is exposed: {analytics:?}"
        );
        for key in ["shareholders", "organs", "relationships"] {
            assert_eq!(
                analytics["graph"][key]["nodes"].as_u64(),
                graph[key]["nodes"]
                    .as_array()
                    .map(|nodes| nodes.len() as u64),
                "{key} node count mirrors structured graph"
            );
            assert_eq!(
                analytics["graph"][key]["edges"].as_u64(),
                graph[key]["edges"]
                    .as_array()
                    .map(|edges| edges.len() as u64),
                "{key} edge count mirrors structured graph"
            );
            assert_eq!(
                analytics["graph"][key]["warnings"].as_u64(),
                graph[key]["warnings"]
                    .as_array()
                    .map(|warnings| warnings.len() as u64),
                "{key} warning count mirrors structured graph"
            );
        }
    }

    #[tokio::test]
    async fn chronology_is_404_for_an_unknown_entity() {
        let state = state_with(certidao_html());
        let missing = Uuid::new_v4();
        let (status, _) = send(state, get(&format!("/v1/entities/{missing}/chronology"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn chronology_returns_sealed_act_projection_without_registry_extract() {
        let state = AppState::default();
        let entity = entity();
        let entity_id = entity.id;
        let book = Book::new(entity_id, BookKind::AssembleiaGeral);
        let book_id = book.id;
        let archived = projected_act(
            0x101,
            book_id,
            "Aprovação de contas",
            ActState::Archived,
            Some(1),
            Some(date!(2026 - 01 - 10)),
            1,
            Some(11),
        );
        let sealed = projected_act(
            0x102,
            book_id,
            "Designação da gerência",
            ActState::Sealed,
            Some(2),
            Some(date!(2026 - 02 - 10)),
            2,
            Some(12),
        );
        let draft = projected_act(
            0x103,
            book_id,
            "Draft must stay out",
            ActState::Draft,
            None,
            Some(date!(2025 - 12 - 31)),
            3,
            None,
        );
        state.entities.write().await.insert(entity_id, entity);
        state.books.write().await.insert(book_id, book);
        {
            let mut acts = state.acts.write().await;
            acts.insert(archived.id, archived);
            acts.insert(sealed.id, sealed);
            acts.insert(draft.id, draft);
        }

        let (status, view) = send(
            state,
            get(&format!("/v1/entities/{}/chronology", entity_id.0)),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "projection-only body: {view}");
        assert_eq!(view["events"].as_array().expect("registry events").len(), 0);
        let projection = &view["sealed_act_projection"];
        assert!(projection.is_object(), "projection is present: {view}");
        assert_eq!(projection["legal_validity_claimed"], false);
        assert_eq!(projection["authority_certified_claimed"], false);
        let events = projection["events"].as_array().expect("projection events");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["ata_number"], 1);
        assert_eq!(events[0]["act_state"], "Archived");
        assert_eq!(events[1]["ata_number"], 2);
        assert_eq!(events[1]["act_state"], "Sealed");
        assert!(
            !serde_json::to_string(projection)
                .expect("projection JSON")
                .contains("Draft must stay out"),
            "draft/review/signing acts are excluded"
        );
        for event in events {
            assert_eq!(event["source"]["kind"], "sealed_act");
            assert!(event["source"]["act_id"].as_str().is_some());
            assert!(event["source"]["book_id"].as_str().is_some());
            assert!(event["source"]["payload_digest"].as_str().is_some());
            assert!(event["source"]["seal_event_seq"].as_u64().is_some());
        }
        let nodes = projection["graph"]["nodes"]
            .as_array()
            .expect("projection nodes");
        assert_eq!(nodes.len(), 2);
        assert!(
            nodes
                .iter()
                .all(|node| node["source"]["kind"] == "sealed_act")
        );
        assert_eq!(
            projection["provenance"]
                .as_array()
                .expect("provenance")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn sealed_act_projection_adds_retification_event_and_edge_without_mutating_acts() {
        let state = AppState::default();
        let entity = entity();
        let entity_id = entity.id;
        let book = Book::new(entity_id, BookKind::AssembleiaGeral);
        let book_id = book.id;
        let original = projected_act(
            0x201,
            book_id,
            "Deliberação original",
            ActState::Sealed,
            Some(1),
            Some(date!(2026 - 03 - 01)),
            4,
            Some(21),
        );
        let original_id = original.id;
        let mut correction = projected_act(
            0x202,
            book_id,
            "Termo de retificação",
            ActState::Sealed,
            Some(2),
            Some(date!(2026 - 03 - 02)),
            5,
            Some(22),
        );
        correction.retifies = Some(original_id);
        let correction_snapshot = correction.clone();

        state.entities.write().await.insert(entity_id, entity);
        state.books.write().await.insert(book_id, book);
        {
            let mut acts = state.acts.write().await;
            acts.insert(original.id, original);
            acts.insert(correction.id, correction);
        }

        let (status, view) = send(
            state.clone(),
            get(&format!("/v1/entities/{}/chronology", entity_id.0)),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "projection body: {view}");
        let projection = &view["sealed_act_projection"];
        let events = projection["events"].as_array().expect("projection events");
        assert!(
            events.iter().any(|event| event["kind"] == "Correction"
                && event["source"]["act_id"] == correction_snapshot.id.to_string()),
            "retifies creates a correction event: {projection}"
        );
        let edges = projection["graph"]["edges"]
            .as_array()
            .expect("projection edges");
        assert!(
            edges.iter().any(|edge| edge["kind"] == "correction"
                && edge["source"]["act_id"] == correction_snapshot.id.to_string()
                && edge["to"] == format!("act:{original_id}")),
            "retifies creates a correction edge sourced to the correction act: {projection}"
        );
        assert!(
            edges
                .iter()
                .all(|edge| edge["source"]["kind"] == "sealed_act")
        );

        let stored_correction = state
            .acts
            .read()
            .await
            .get(&correction_snapshot.id)
            .cloned()
            .expect("stored correction");
        assert_eq!(stored_correction, correction_snapshot);
    }

    #[tokio::test]
    async fn chronology_requires_a_session() {
        let state = state_with(certidao_html());
        // No x-chancela-session header → 401 (the gated-read policy, like /registry).
        let response = crate::router(state)
            .oneshot(get(&format!("/v1/entities/{}/chronology", Uuid::new_v4())))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
