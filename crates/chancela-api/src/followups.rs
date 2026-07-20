//! Act-scoped follow-up/task endpoints.
//!
//! Follow-ups live outside `Act` JSON so post-deliberation work can be tracked without mutating a
//! sealed act. Mutations append `follow_up.*` ledger events and persist the task row in the same
//! durable transaction.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_authz::Permission;
use chancela_core::ActId;
use chancela_store::{StoredFollowUp, StoredFollowUpStatus};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_act, scope_of_follow_up};
use crate::dto::{CompleteFollowUp, CreateFollowUp, FollowUpView, PatchFollowUp, parse_date};
use crate::error::ApiError;

/// `GET /v1/acts/{id}/follow-ups` — list task rows for one act, open first.
pub async fn list_follow_ups(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<Vec<FollowUpView>>, ApiError> {
    let act_id = ActId(id);
    require_permission(
        &state,
        &actor,
        Permission::ActRead,
        scope_of_act(&state, act_id).await,
    )
    .await?;

    let acts = state.acts.read().await;
    if !acts.contains_key(&act_id) {
        return Err(ApiError::NotFound);
    }
    drop(acts);

    let mut rows = state
        .follow_ups
        .read()
        .await
        .values()
        .filter(|follow_up| follow_up.act_id == act_id)
        .cloned()
        .collect::<Vec<_>>();
    sort_follow_ups(&mut rows);

    Ok(Json(rows.iter().map(FollowUpView::from).collect()))
}

/// `POST /v1/acts/{id}/follow-ups` — create a mutable follow-up row for an act.
pub async fn create_follow_up(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateFollowUp>,
) -> Result<(StatusCode, Json<FollowUpView>), ApiError> {
    let act_id = ActId(id);
    require_permission(
        &state,
        &actor,
        Permission::ActEdit,
        scope_of_act(&state, act_id).await,
    )
    .await?;
    let actor = actor.resolve(&req.actor);
    let title = normalized_required(req.title, "follow-up title")?;
    let due_date = parse_optional_date(req.due_date)?;

    // acts -> follow_ups -> ledger.
    let acts = state.acts.read().await;
    let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
    let scope = format!("book:{}/act:{}", act.book_id, act.id);

    let follow_up = StoredFollowUp {
        id: Uuid::new_v4().to_string(),
        act_id,
        agenda_number: req.agenda_number,
        deliberation_index: req.deliberation_index,
        title,
        detail: normalize_optional(req.detail),
        due_date,
        assignee: normalize_optional(req.assignee),
        assignee_display: normalize_optional(req.assignee_display),
        status: StoredFollowUpStatus::Open,
        created_at: OffsetDateTime::now_utc(),
        created_by: actor.clone(),
        completed_at: None,
        completed_by: None,
    };
    let payload = serde_json::to_vec(&FollowUpView::from(&follow_up))?;

    let mut follow_ups = state.follow_ups.write().await;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "follow_up.created",
        Some("create follow-up"),
        &payload,
    )?;
    let follow_up_for_store = follow_up.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_follow_up(&follow_up_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;

    let view = FollowUpView::from(&follow_up);
    follow_ups.insert(follow_up.id.clone(), follow_up);
    Ok((StatusCode::CREATED, Json(view)))
}

/// `PATCH /v1/follow-ups/{id}` — update editable metadata on an open follow-up row.
pub async fn patch_follow_up(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchFollowUp>,
) -> Result<Json<FollowUpView>, ApiError> {
    require_permission(
        &state,
        &actor,
        Permission::ActEdit,
        scope_of_follow_up(&state, &id).await,
    )
    .await?;
    let actor = actor.resolve(&req.actor);

    // follow_ups -> ledger.
    let mut follow_ups = state.follow_ups.write().await;
    let follow_up = follow_ups.get_mut(&id).ok_or(ApiError::NotFound)?;
    if follow_up.status == StoredFollowUpStatus::Completed {
        return Err(ApiError::Conflict(format!(
            "follow-up {} is already completed",
            follow_up.id
        )));
    }

    let mut next = follow_up.clone();
    apply_patch(&mut next, req)?;
    let scope = format!("act:{}", next.act_id);
    let payload = serde_json::to_vec(&FollowUpView::from(&next))?;

    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "follow_up.updated",
        Some("update follow-up"),
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_follow_up(&next_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;

    *follow_up = next;
    Ok(Json(FollowUpView::from(&*follow_up)))
}

/// `POST /v1/follow-ups/{id}/complete` — mark an open follow-up completed.
pub async fn complete_follow_up(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CompleteFollowUp>,
) -> Result<Json<FollowUpView>, ApiError> {
    require_permission(
        &state,
        &actor,
        Permission::ActEdit,
        scope_of_follow_up(&state, &id).await,
    )
    .await?;
    let actor = actor.resolve(&req.actor);

    // follow_ups -> ledger.
    let mut follow_ups = state.follow_ups.write().await;
    let follow_up = follow_ups.get_mut(&id).ok_or(ApiError::NotFound)?;
    if follow_up.status == StoredFollowUpStatus::Completed {
        return Err(ApiError::Conflict(format!(
            "follow-up {} is already completed",
            follow_up.id
        )));
    }

    let mut next = follow_up.clone();
    next.status = StoredFollowUpStatus::Completed;
    next.completed_at = Some(OffsetDateTime::now_utc());
    next.completed_by = Some(actor.clone());

    let scope = format!("act:{}", next.act_id);
    let payload = serde_json::to_vec(&FollowUpView::from(&next))?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "follow_up.completed",
        Some("complete follow-up"),
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_follow_up(&next_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;

    *follow_up = next;
    Ok(Json(FollowUpView::from(&*follow_up)))
}

fn apply_patch(follow_up: &mut StoredFollowUp, req: PatchFollowUp) -> Result<(), ApiError> {
    if let Some(title) = req.title {
        follow_up.title = normalized_required(title, "follow-up title")?;
    }
    if let Some(detail) = req.detail {
        follow_up.detail = normalize_optional(detail);
    }
    if let Some(due_date) = req.due_date {
        follow_up.due_date = parse_optional_date(due_date)?;
    }
    if let Some(assignee) = req.assignee {
        follow_up.assignee = normalize_optional(assignee);
    }
    if let Some(assignee_display) = req.assignee_display {
        follow_up.assignee_display = normalize_optional(assignee_display);
    }
    if let Some(agenda_number) = req.agenda_number {
        follow_up.agenda_number = agenda_number;
    }
    if let Some(deliberation_index) = req.deliberation_index {
        follow_up.deliberation_index = deliberation_index;
    }
    Ok(())
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn normalized_required(value: String, field: &str) -> Result<String, ApiError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(ApiError::Unprocessable(format!(
            "{field} must not be empty"
        )));
    }
    Ok(value)
}

fn parse_optional_date(value: Option<String>) -> Result<Option<time::Date>, ApiError> {
    value
        .map(|value| {
            let value = value.trim().to_owned();
            if value.is_empty() {
                return Ok(None);
            }
            parse_date(&value).map(Some)
        })
        .transpose()
        .map(Option::flatten)
}

fn sort_follow_ups(rows: &mut [StoredFollowUp]) {
    rows.sort_by(|a, b| {
        let a_status = match a.status {
            StoredFollowUpStatus::Open => 0,
            StoredFollowUpStatus::Completed => 1,
        };
        let b_status = match b.status {
            StoredFollowUpStatus::Open => 0,
            StoredFollowUpStatus::Completed => 1,
        };
        a_status
            .cmp(&b_status)
            .then_with(|| a.created_at.cmp(&b.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
}
