//! Entity endpoints (contract §2.3) — unchanged from the scaffold, moved here for the
//! module split. Entities are the root object: books belong to an entity, acts to a book.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_authz::{Permission, Scope};
use chancela_core::{
    Book, BookId, BookState, Entity, EntityId, EntityKind, Nipc, StatuteOverrides,
};
use chancela_ledger::{ChainId, Event};
use serde::Deserialize;
use time::{Date, Month};
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, require_permission, scope_of_book, scope_of_entity};
use crate::dto::{
    BookStateCountsView, BookView, EntityActivitySummaryView, EntityListItemView, EntityView,
    LedgerEventView, read_redaction_for_actor,
};
use crate::error::ApiError;

/// Justification recorded on the `entity.created` event when the NIPC-validation override stored
/// an unvalidated identifier (see [`create_entity`]). Frozen wording so the override is greppable
/// in the audit trail.
const NIPC_OVERRIDE_JUSTIFICATION: &str = "nipc validation overridden (stored unvalidated)";

/// Request body for `POST /v1/entities`.
///
/// The [`EntityId`] and [`chancela_core::EntityFamily`] are derived server-side (the family
/// from `kind`), so callers cannot forge an inconsistent entity.
#[derive(Deserialize)]
pub struct CreateEntity {
    name: String,
    /// Raw NIPC; validated (format + control digit) before the entity is built, unless
    /// `allow_invalid_nipc` is set and validation fails (see that field).
    nipc: String,
    seat: String,
    kind: EntityKind,
    /// NIPC-validation override. When `false` (the default) an invalid NIPC is rejected with
    /// `422`, exactly as before. When `true` **and** the NIPC fails [`Nipc::parse`], the raw
    /// identifier is stored [`unvalidated`](Nipc::unvalidated) and the entity is created anyway —
    /// for foreign entities, special registrations, or legacy data that legitimately lack a
    /// control-digit-valid PT NIPC. A NIPC that *does* parse is always stored validated, override
    /// or not.
    #[serde(default)]
    allow_invalid_nipc: bool,
    /// Fiscal year end as `MM-DD`, if recorded for the entity.
    fiscal_year_end: Option<String>,
}

/// Create an entity, record an `entity.created` ledger event, and return it with `201`.
pub async fn create_entity(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateEntity>,
) -> Result<(StatusCode, Json<EntityView>), ApiError> {
    // RBAC (t64-E3): creating an entity is a Global op (no entity exists yet to scope to).
    require_permission(&state, &actor, Permission::EntityCreate, Scope::Global).await?;
    // A parseable NIPC is always stored validated; the override only rescues a parse failure.
    let nipc = match Nipc::parse(&req.nipc) {
        Ok(nipc) => nipc,
        Err(_) if req.allow_invalid_nipc => Nipc::unvalidated(&req.nipc),
        Err(e) => return Err(e.into()),
    };
    let overridden = !nipc.is_validated();
    let fiscal_year_end = normalize_fiscal_year_end(req.fiscal_year_end)?;
    let mut entity = Entity::new(req.name, nipc, req.seat, req.kind);
    entity.fiscal_year_end = fiscal_year_end;

    // Digest the created entity into the audit chain before it becomes queryable, so the
    // ledger is the source of truth for "what happened" (DAT-10). The entity's own serialization
    // already carries `nipc.validated: false` for an override; the justification makes the
    // deliberate skip explicit and greppable in the audit trail.
    let payload = serde_json::to_vec(&entity)?;
    let justification = overridden.then_some(NIPC_OVERRIDE_JUSTIFICATION);
    let actor = actor.resolve("api");
    let scope = entity.id.to_string();
    {
        // Append the event and, when persistent, durably write the event + the new entity row in
        // one transaction. A store failure rolls back the append and returns 500 without mutating
        // the read model (below), so memory and disk never diverge.
        let mut ledger = state.ledger.write().await;
        ledger.append(&actor, &scope, "entity.created", justification, &payload);
        state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_entity(&entity))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    let view = EntityView::from(&entity);
    state.entities.write().await.insert(entity.id, entity);
    Ok((StatusCode::CREATED, Json(view)))
}

/// Justification recorded on the `entity.statute_updated` event (ENT-03 audit trail). Frozen
/// wording so a statute-overlay edit is greppable in the ledger.
const STATUTE_UPDATE_JUSTIFICATION: &str = "entity statute overlay updated";

/// Request body for `PATCH /v1/entities/{id}`. Currently the statute overlay only (ENT-03); the
/// body is extendable. Uses [`double_option`](crate::dto::double_option) so an absent key leaves
/// the overlay untouched, an explicit `null` clears it, and an object sets it.
#[derive(Deserialize)]
pub struct PatchEntity {
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    statute: Option<Option<StatuteOverrides>>,
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    fiscal_year_end: Option<Option<String>>,
}

/// `PATCH /v1/entities/{id}` — edit the per-entity statute overlay (ENT-03), append an
/// `entity.statute_updated` ledger event, durably write the entity through, and return the
/// updated [`EntityView`]. `404` when the entity is unknown.
pub async fn patch_entity(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchEntity>,
) -> Result<Json<EntityView>, ApiError> {
    // RBAC (t64-E3): editing an entity is scoped to that entity.
    require_permission(
        &state,
        &actor,
        Permission::EntityUpdate,
        scope_of_entity(EntityId(id)),
    )
    .await?;
    let actor = actor.resolve("api");
    // entities → ledger (the global lock order); attestation sidecar acquired last.
    let mut entities = state.entities.write().await;
    let mut ledger = state.ledger.write().await;

    let entity = entities.get_mut(&EntityId(id)).ok_or(ApiError::NotFound)?;

    // Apply to a clone so the in-memory map is mutated only after the durable write commits (a
    // store failure rolls back the appended event and leaves the entity untouched).
    let mut next = entity.clone();
    if let Some(statute) = req.statute {
        next.statute = statute;
    }
    if let Some(fiscal_year_end) = req.fiscal_year_end {
        next.fiscal_year_end = normalize_fiscal_year_end(fiscal_year_end)?;
    }

    let scope = next.id.to_string();
    let payload = serde_json::to_vec(&next)?;
    ledger.append(
        &actor,
        &scope,
        "entity.statute_updated",
        Some(STATUTE_UPDATE_JUSTIFICATION),
        &payload,
    );
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_entity(&next))?;
    state.attest_latest(&attestor, &ledger).await;
    *entity = next;

    Ok(Json(EntityView::from(&*entity)))
}

pub(crate) fn normalize_fiscal_year_end(value: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    let Some((month, day)) = value.split_once('-') else {
        return Err(invalid_fiscal_year_end());
    };
    if month.len() != 2 || day.len() != 2 {
        return Err(invalid_fiscal_year_end());
    }
    let month = month.parse::<u8>().map_err(|_| invalid_fiscal_year_end())?;
    let day = day.parse::<u8>().map_err(|_| invalid_fiscal_year_end())?;
    let month = Month::try_from(month).map_err(|_| invalid_fiscal_year_end())?;
    Date::from_calendar_date(2000, month, day).map_err(|_| invalid_fiscal_year_end())?;
    let month_num = month as u8;
    Ok(Some(format!("{month_num:02}-{day:02}")))
}

fn invalid_fiscal_year_end() -> ApiError {
    ApiError::Unprocessable("fiscal_year_end must be MM-DD".to_owned())
}

/// List entities the caller may read (contract §2.3; RBAC list-filtering, plan §3.3 note²): requires
/// a valid session and returns only rows the caller holds `entity.read` at (a Global reader sees all;
/// an entity-scoped reader only their entity). No enumeration of unreadable rows — a caller with no
/// read authority gets an empty list, never a status that reveals what exists.
pub async fn list_entities(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<EntityListItemView>>, ApiError> {
    let authz = crate::authz::authorizer(&state, &actor).await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let entities = state.entities.read().await;
    let visible: Vec<_> = entities
        .values()
        .filter(|e| authz.permits(Permission::EntityRead, scope_of_entity(e.id)))
        .collect();

    let visible_entity_ids: HashSet<_> = visible.iter().map(|e| e.id).collect();
    let books = state.books.read().await;
    let readable_books: Vec<_> = books
        .values()
        .filter(|b| visible_entity_ids.contains(&b.entity_id))
        .filter(|b| authz.permits(Permission::BookRead, scope_of_book(b.id)))
        .collect();

    let ledger = if authz.permits(Permission::LedgerRead, Scope::Global) {
        Some(state.ledger.read().await)
    } else {
        None
    };
    let events = ledger.as_ref().map(|ledger| ledger.events());
    let mut summaries =
        entity_activity_summaries(&visible_entity_ids, readable_books.iter().copied(), events);

    let out = visible
        .into_iter()
        .map(|e| EntityListItemView {
            entity: EntityView::build(e, redaction),
            activity_summary: summaries
                .remove(&e.id)
                .unwrap_or_else(empty_activity_summary),
        })
        .collect();
    Ok(Json(out))
}

struct EntityActivitySummaryBuilder<'book, 'event> {
    last_book: Option<&'book Book>,
    book_state_counts: BookStateCountsView,
    last_change: Option<&'event Event>,
}

fn entity_activity_summaries<'book, 'event>(
    entity_ids: &HashSet<EntityId>,
    books: impl IntoIterator<Item = &'book Book>,
    events: Option<&'event [Event]>,
) -> HashMap<EntityId, EntityActivitySummaryView> {
    let mut summaries: HashMap<_, _> = entity_ids
        .iter()
        .copied()
        .map(|id| {
            (
                id,
                EntityActivitySummaryBuilder {
                    last_book: None,
                    book_state_counts: BookStateCountsView::default(),
                    last_change: None,
                },
            )
        })
        .collect();
    let mut book_entity_ids = HashMap::new();

    for book in books {
        book_entity_ids.insert(book.id, book.entity_id);
        let Some(summary) = summaries.get_mut(&book.entity_id) else {
            continue;
        };
        summary.book_state_counts.add(book.state);
        if summary
            .last_book
            .is_none_or(|current| compare_last_book(book, current) == Ordering::Greater)
        {
            summary.last_book = Some(book);
        }
    }

    if let Some(events) = events {
        for event in events {
            for entity_id in collect_event_entity_ids(event, entity_ids, &book_entity_ids) {
                let Some(summary) = summaries.get_mut(&entity_id) else {
                    continue;
                };
                if summary.last_change.is_none_or(|current| {
                    compare_event_recency(event, current) == Ordering::Greater
                }) {
                    summary.last_change = Some(event);
                }
            }
        }
    }

    summaries
        .into_iter()
        .map(|(id, summary)| {
            (
                id,
                EntityActivitySummaryView {
                    last_book: summary.last_book.map(BookView::from),
                    book_state_counts: summary.book_state_counts,
                    last_change: summary.last_change.map(LedgerEventView::from),
                },
            )
        })
        .collect()
}

fn empty_activity_summary() -> EntityActivitySummaryView {
    EntityActivitySummaryView {
        last_book: None,
        book_state_counts: BookStateCountsView::default(),
        last_change: None,
    }
}

fn compare_last_book(candidate: &Book, current: &Book) -> Ordering {
    book_activity_date(candidate)
        .cmp(&book_activity_date(current))
        .then_with(|| candidate.last_ata_number.cmp(&current.last_ata_number))
        .then_with(|| book_state_rank(candidate.state).cmp(&book_state_rank(current.state)))
        .then_with(|| candidate.id.to_string().cmp(&current.id.to_string()))
}

fn book_activity_date(book: &Book) -> Option<Date> {
    let opening = book.termo_abertura.as_ref().map(|t| t.opening_date);
    let closing = book.termo_encerramento.as_ref().map(|t| t.closing_date);
    opening.max(closing)
}

const fn book_state_rank(state: BookState) -> u8 {
    match state {
        BookState::Open => 2,
        BookState::Created => 1,
        BookState::Closed => 0,
    }
}

fn compare_event_recency(candidate: &Event, current: &Event) -> Ordering {
    candidate
        .timestamp
        .cmp(&current.timestamp)
        .then_with(|| candidate.seq.cmp(&current.seq))
}

fn collect_event_entity_ids(
    event: &Event,
    entity_ids: &HashSet<EntityId>,
    book_entity_ids: &HashMap<BookId, EntityId>,
) -> HashSet<EntityId> {
    let mut ids = HashSet::new();
    add_entity_id(event.scope.as_str(), entity_ids, &mut ids);
    add_segment_entity_ids(event.scope.as_str(), "entity:", entity_ids, &mut ids);
    add_segment_entity_ids(event.scope.as_str(), "company:", entity_ids, &mut ids);
    add_segment_book_entity_ids(event.scope.as_str(), book_entity_ids, &mut ids);

    for link in &event.links {
        match &link.chain {
            ChainId::Company(raw) => add_entity_id(raw, entity_ids, &mut ids),
            ChainId::Book(raw) => add_book_entity_id(raw, book_entity_ids, &mut ids),
            ChainId::Global | ChainId::Application => {}
        }
    }

    ids
}

fn add_segment_entity_ids(
    value: &str,
    prefix: &str,
    entity_ids: &HashSet<EntityId>,
    ids: &mut HashSet<EntityId>,
) {
    for segment in value.split('/') {
        if let Some(raw) = segment.strip_prefix(prefix).filter(|raw| !raw.is_empty()) {
            add_entity_id(raw, entity_ids, ids);
        }
    }
}

fn add_segment_book_entity_ids(
    value: &str,
    book_entity_ids: &HashMap<BookId, EntityId>,
    ids: &mut HashSet<EntityId>,
) {
    for segment in value.split('/') {
        if let Some(raw) = segment.strip_prefix("book:").filter(|raw| !raw.is_empty()) {
            add_book_entity_id(raw, book_entity_ids, ids);
        }
    }
}

fn add_entity_id(raw: &str, entity_ids: &HashSet<EntityId>, ids: &mut HashSet<EntityId>) {
    let Ok(uuid) = Uuid::parse_str(raw) else {
        return;
    };
    let id = EntityId(uuid);
    if entity_ids.contains(&id) {
        ids.insert(id);
    }
}

fn add_book_entity_id(
    raw: &str,
    book_entity_ids: &HashMap<BookId, EntityId>,
    ids: &mut HashSet<EntityId>,
) {
    let Ok(uuid) = Uuid::parse_str(raw) else {
        return;
    };
    if let Some(entity_id) = book_entity_ids.get(&BookId(uuid)) {
        ids.insert(*entity_id);
    }
}

/// Fetch one entity by id, or return `404`. RBAC (t64-E3): `entity.read` scoped to the entity.
pub async fn get_entity(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<EntityView>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::EntityRead, scope_of_entity(EntityId(id)))?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let entities = state.entities.read().await;
    entities
        .get(&EntityId(id))
        .map(|e| Json(EntityView::build(e, redaction)))
        .ok_or(ApiError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use chancela_authz::{
        GUEST_ROLE_ID, LEITOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId, Scope,
    };
    use chancela_core::book::ClosingReason;
    use chancela_core::{BookKind, NumberingScheme, TermoDeAbertura, TermoDeEncerramento};
    use serde_json::{Value, json};
    use time::macros::date;
    use tower::ServiceExt;

    async fn send_raw(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
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

    fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
        req.headers_mut().insert(
            "x-chancela-session",
            token.parse().expect("valid session header"),
        );
        req
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

    async fn token_for_role(state: &AppState, username: &str, role_id: RoleId) -> String {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;

        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }

        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: username.to_owned(),
            display_name: username.to_owned(),
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
        };
        state.users.write().await.insert(uid, user);

        let token = Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    #[tokio::test]
    async fn guest_entity_redaction_hides_nipc_and_seat_while_leitor_keeps_them() {
        let state = AppState::default();
        let owner = token_for_role(&state, "owner", OWNER_ROLE_ID).await;
        let (status, created) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({
                        "name": "Encosto Estratégico, S.A.",
                        "nipc": "503004642",
                        "seat": "Rua da Liberdade, Lisboa",
                        "kind": "SociedadeAnonima",
                    }),
                ),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().expect("entity id");

        let guest = token_for_role(&state, "guest", GUEST_ROLE_ID).await;
        let (status, guest_detail) = send_raw(
            state.clone(),
            with_session(get(&format!("/v1/entities/{id}")), &guest),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(guest_detail["nipc"], crate::dto::REDACTED);
        assert_eq!(guest_detail["nipc_validated"], false);
        assert_eq!(guest_detail["seat"], crate::dto::REDACTED);

        let (status, guest_list) =
            send_raw(state.clone(), with_session(get("/v1/entities"), &guest)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(guest_list[0]["nipc"], crate::dto::REDACTED);
        assert_eq!(guest_list[0]["seat"], crate::dto::REDACTED);

        let redacted = guest_list.to_string();
        assert!(!redacted.contains("503004642"), "NIPC leaked: {redacted}");
        assert!(
            !redacted.contains("Rua da Liberdade"),
            "seat leaked: {redacted}"
        );

        let leitor = token_for_role(&state, "leitor", LEITOR_ROLE_ID).await;
        let (status, reader_detail) = send_raw(
            state,
            with_session(get(&format!("/v1/entities/{id}")), &leitor),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reader_detail["nipc"], "503004642");
        assert_eq!(reader_detail["nipc_validated"], true);
        assert_eq!(reader_detail["seat"], "Rua da Liberdade, Lisboa");
    }

    #[tokio::test]
    async fn list_entities_returns_activity_summary_from_full_state_and_ledger() {
        let state = AppState::default();
        let owner = token_for_role(&state, "owner", OWNER_ROLE_ID).await;
        let (status, created) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({
                        "name": "Encosto Estratégico, S.A.",
                        "nipc": "503004642",
                        "seat": "Lisboa",
                        "kind": "SociedadeAnonima",
                    }),
                ),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_uuid =
            Uuid::parse_str(created["id"].as_str().expect("entity id")).expect("entity id is uuid");
        let entity_id = EntityId(entity_uuid);
        let entity = state
            .entities
            .read()
            .await
            .get(&entity_id)
            .expect("entity stored")
            .clone();

        let mut open_book = Book::new(entity_id, BookKind::AssembleiaGeral);
        open_book
            .open(TermoDeAbertura {
                entity_name: entity.name.clone(),
                entity_nipc: entity.nipc.to_string(),
                entity_seat: entity.seat.clone(),
                purpose: "Assembleia anual 2026".to_owned(),
                numbering_scheme: NumberingScheme::Sequential,
                opening_date: date!(2026 - 01 - 10),
                required_signatories: vec!["Administrador".to_owned()],
            })
            .expect("open book");
        for _ in 0..4 {
            open_book.assign_next_ata_number().expect("ata number");
        }

        let mut closed_book =
            Book::new_successor(entity_id, BookKind::ConselhoFiscal, open_book.id);
        closed_book
            .open(TermoDeAbertura {
                entity_name: entity.name.clone(),
                entity_nipc: entity.nipc.to_string(),
                entity_seat: entity.seat.clone(),
                purpose: "Fiscalização 2026".to_owned(),
                numbering_scheme: NumberingScheme::Sequential,
                opening_date: date!(2026 - 02 - 01),
                required_signatories: vec!["Presidente".to_owned()],
            })
            .expect("open successor");
        for _ in 0..8 {
            closed_book.assign_next_ata_number().expect("ata number");
        }
        closed_book
            .close(TermoDeEncerramento {
                ata_count: 0,
                reason: ClosingReason::BookFull,
                closing_date: date!(2026 - 06 - 30),
                required_signatories: vec!["Presidente".to_owned()],
            })
            .expect("close successor");

        let open_scope = format!("entity:{}/book:{}", entity_id, open_book.id);
        let closed_scope = format!("entity:{}/book:{}", entity_id, closed_book.id);
        let closed_book_id = closed_book.id.to_string();

        {
            let mut books = state.books.write().await;
            books.insert(open_book.id, open_book.clone());
            books.insert(closed_book.id, closed_book.clone());
        }

        let (close_seq, ledger_len) = {
            let mut ledger = state.ledger.write().await;
            ledger.append(
                "amelia.marques",
                &open_scope,
                "book.opened",
                None,
                &serde_json::to_vec(open_book.termo_abertura.as_ref().expect("opened"))
                    .expect("payload"),
            );
            ledger.append(
                "bruno.costa",
                &closed_scope,
                "book.opened",
                None,
                &serde_json::to_vec(closed_book.termo_abertura.as_ref().expect("opened"))
                    .expect("payload"),
            );
            let close = ledger
                .append(
                    "bruno.costa",
                    &closed_scope,
                    "book.closed",
                    None,
                    &serde_json::to_vec(closed_book.termo_encerramento.as_ref().expect("closed"))
                        .expect("payload"),
                )
                .seq;

            for i in 0..1005 {
                ledger.append(
                    "system",
                    "settings",
                    "settings.updated",
                    None,
                    format!("noise-{i}").as_bytes(),
                );
            }
            (close, ledger.len())
        };
        assert!(
            close_seq < ledger_len as u64 - 1000,
            "book.closed is outside the latest 1000 ledger events"
        );

        let (status, list) =
            send_raw(state.clone(), with_session(get("/v1/entities"), &owner)).await;
        assert_eq!(status, StatusCode::OK);
        let row = list
            .as_array()
            .expect("entity list")
            .iter()
            .find(|row| row["id"] == created["id"])
            .expect("created entity row");
        let summary = &row["activity_summary"];

        assert_eq!(summary["last_book"]["id"], closed_book_id);
        assert_eq!(summary["last_book"]["state"], "Closed");
        assert_eq!(
            summary["book_state_counts"],
            json!({ "created": 0, "open": 1, "closed": 1 })
        );
        assert_eq!(summary["last_change"]["kind"], "book.closed");
        assert_eq!(summary["last_change"]["scope"], closed_scope);
        assert_eq!(summary["last_change"]["seq"], close_seq);
    }
}
