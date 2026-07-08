//! Chronology / relationship-graph endpoint (spec DOC-30/31/32) — a native, **explainable** graph
//! feature over a stored [`RegistryExtract`].
//!
//! `GET /v1/entities/{id}/chronology` builds the normalized event timeline (DOC-30) and the Mermaid
//! diagram set (DOC-31) from the entity's imported certidão extract and returns them as thin wire
//! views (house convention). Every event carries its `source_inscription` (DOC-32 provenance).
//! `404` when the entity is unknown or nothing has been imported. Requires a valid session, exactly
//! like its sibling `GET /v1/entities/{id}/registry` (both read the same stored extract).

use axum::Json;
use axum::extract::{Path, State};
use chancela_core::EntityId;
use chancela_registry::RegistryExtract;
use chancela_registry::chronology::{Chronology, ChronologyEvent, ChronologyKind};
use serde::Serialize;
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::error::ApiError;

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

/// The chronology response: the ordered event timeline plus the Mermaid diagram set.
#[derive(Serialize)]
pub struct ChronologyView {
    pub events: Vec<ChronologyEventView>,
    pub mermaid: MermaidBundleView,
}

impl ChronologyView {
    /// Build the full view from an extract (DOC-30 events + DOC-31 Mermaid).
    pub fn build(extract: &RegistryExtract) -> Self {
        let chrono = Chronology::build(extract);
        let events = chrono
            .events
            .iter()
            .map(ChronologyEventView::from)
            .collect();
        let mermaid = MermaidBundleView {
            shareholders: chrono.shareholders_mermaid(extract),
            organs: chrono.organs_mermaid(extract),
            relationships: chrono.relationships_mermaid(extract),
        };
        ChronologyView { events, mermaid }
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
    _actor: CurrentActor,
) -> Result<Json<ChronologyView>, ApiError> {
    let extracts = state.registry_extracts.read().await;
    let extract = extracts.get(&EntityId(id)).ok_or(ApiError::NotFound)?;
    Ok(Json(ChronologyView::build(extract)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::SESSION_TTL_SECS;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use std::sync::Arc;
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
        use time::format_description::well_known::Rfc3339;
        let uid = UserId(uuid::Uuid::new_v4());
        let user = User {
            id: uid,
            username: "test.actor".to_owned(),
            display_name: "Test Actor".to_owned(),
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
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
    }

    #[tokio::test]
    async fn chronology_is_404_for_an_unknown_entity() {
        let state = state_with(certidao_html());
        let missing = Uuid::new_v4();
        let (status, _) = send(state, get(&format!("/v1/entities/{missing}/chronology"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
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
