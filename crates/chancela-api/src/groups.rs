//! Tenant-local company groups, shared versioned template libraries, and cross-entity dashboards
//! (ENT-C7, DAT-03, WFL-32).
//!
//! Group is deliberately not an authz scope or ledger chain. Every handler authorizes against the
//! owning tenant and every membership mutation additionally authorizes the entity. Group/library
//! events use the canonical `tenant:{id}` scope; membership uses
//! `tenant:{id}/entity:{id}`, which the ledger maps to the existing tenant + company chains.

use std::collections::{BTreeMap, HashSet};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_authz::Permission;
use chancela_core::{
    ActState, BookState, CompanyGroup, Entity, EntityId, GroupId, GroupTemplateLibrary,
    GroupTemplateLibraryRevision, TemplateLibraryId, TenantId,
};
use chancela_ledger::ChainId;
use chancela_store::StoredFollowUpStatus;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{
    authorizer, require_permission, scope_of_book, scope_of_entity, scope_of_template_library,
    scope_of_tenant,
};
use crate::dto::{EntityView, LedgerEventView, read_redaction_for_actor};
use crate::{ApiError, AppState};

const MAX_NAME_CHARS: usize = 200;
const MAX_DESCRIPTION_CHARS: usize = 2_000;
const MAX_LIBRARY_TEMPLATE_IDS: usize = 512;
const GROUP_AUDIT_EVENT_LIMIT: usize = 50;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CompanyGroupView {
    #[serde(flatten)]
    group: CompanyGroup,
    member_count: usize,
    template_library_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GroupTemplateLibraryView {
    #[serde(flatten)]
    library: GroupTemplateLibrary,
    current_revision: Option<GroupTemplateLibraryRevision>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GroupReminderView {
    id: String,
    act_id: String,
    title: String,
    due_date: Option<String>,
    overdue: bool,
    assignee: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct GroupDashboardView {
    group: CompanyGroupView,
    member_entities: Vec<EntityView>,
    books_total: usize,
    books_by_state: BTreeMap<String, usize>,
    acts_total: usize,
    acts_by_state: BTreeMap<String, usize>,
    reminders_open: usize,
    reminders_overdue: usize,
    reminders: Vec<GroupReminderView>,
    recent_audit_events: Vec<LedgerEventView>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateGroupBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PatchGroupBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    description: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateTemplateLibraryBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    template_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PatchTemplateLibraryBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    description: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AppendTemplateLibraryRevisionBody {
    template_ids: Vec<String>,
}

fn tenant_id(raw: Uuid) -> TenantId {
    TenantId(raw)
}

fn group_id(raw: Uuid) -> GroupId {
    GroupId(raw)
}

fn library_id(raw: Uuid) -> TemplateLibraryId {
    TemplateLibraryId(raw)
}

fn tenant_scope(tenant_id: TenantId) -> String {
    format!("tenant:{tenant_id}")
}

fn entity_ledger_scope(tenant_id: TenantId, entity_id: EntityId) -> String {
    format!("tenant:{tenant_id}/entity:{entity_id}")
}

fn audit_object(group_id: GroupId, library_id: Option<TemplateLibraryId>) -> String {
    match library_id {
        Some(library_id) => format!("group:{group_id}/library:{library_id}"),
        None => format!("group:{group_id}"),
    }
}

fn normalized_required(value: String, field: &str, max: usize) -> Result<String, ApiError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(ApiError::Unprocessable(format!(
            "{field} must not be empty"
        )));
    }
    if value.chars().count() > max {
        return Err(ApiError::Unprocessable(format!(
            "{field} exceeds {max} characters"
        )));
    }
    Ok(value)
}

fn normalized_optional(value: Option<String>, field: &str) -> Result<Option<String>, ApiError> {
    value
        .map(|value| {
            let value = value.trim().to_owned();
            if value.chars().count() > MAX_DESCRIPTION_CHARS {
                return Err(ApiError::Unprocessable(format!(
                    "{field} exceeds {MAX_DESCRIPTION_CHARS} characters"
                )));
            }
            Ok((!value.is_empty()).then_some(value))
        })
        .transpose()
        .map(Option::flatten)
}

fn name_key(name: &str) -> String {
    name.chars().flat_map(char::to_lowercase).collect()
}

fn ensure_unique_group_name(
    groups: &std::collections::HashMap<GroupId, CompanyGroup>,
    tenant_id: TenantId,
    group_id: Option<GroupId>,
    name: &str,
) -> Result<(), ApiError> {
    let key = name_key(name);
    if groups.values().any(|group| {
        group.tenant_id == tenant_id
            && !group.is_archived()
            && Some(group.id) != group_id
            && name_key(&group.name) == key
    }) {
        Err(ApiError::Conflict(
            "an active group with that name already exists in this tenant".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn ensure_unique_library_name(
    libraries: &std::collections::HashMap<TemplateLibraryId, GroupTemplateLibrary>,
    group_id: GroupId,
    library_id: Option<TemplateLibraryId>,
    name: &str,
) -> Result<(), ApiError> {
    let key = name_key(name);
    if libraries.values().any(|library| {
        library.group_id == group_id
            && !library.is_archived()
            && Some(library.id) != library_id
            && name_key(&library.name) == key
    }) {
        Err(ApiError::Conflict(
            "an active template library with that name already exists in this group".to_owned(),
        ))
    } else {
        Ok(())
    }
}

async fn require_tenant(
    state: &AppState,
    actor: &CurrentActor,
    permission: Permission,
    tenant_id: TenantId,
) -> Result<(), ApiError> {
    require_permission(state, actor, permission, scope_of_tenant(tenant_id)).await
}

async fn require_known_tenant(state: &AppState, tenant_id: TenantId) -> Result<(), ApiError> {
    if state.tenants.read().await.contains_key(&tenant_id) {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

fn group_for_path(
    groups: &std::collections::HashMap<GroupId, CompanyGroup>,
    tenant_id: TenantId,
    group_id: GroupId,
) -> Result<&CompanyGroup, ApiError> {
    groups
        .get(&group_id)
        .filter(|group| group.tenant_id == tenant_id)
        .ok_or(ApiError::NotFound)
}

fn library_for_path(
    libraries: &std::collections::HashMap<TemplateLibraryId, GroupTemplateLibrary>,
    tenant_id: TenantId,
    group_id: GroupId,
    library_id: TemplateLibraryId,
) -> Result<&GroupTemplateLibrary, ApiError> {
    libraries
        .get(&library_id)
        .filter(|library| library.tenant_id == tenant_id && library.group_id == group_id)
        .ok_or(ApiError::NotFound)
}

fn current_revision(
    revisions: &std::collections::HashMap<
        (GroupId, TemplateLibraryId, u64),
        GroupTemplateLibraryRevision,
    >,
    group_id: GroupId,
    library_id: TemplateLibraryId,
) -> Option<GroupTemplateLibraryRevision> {
    revisions
        .values()
        .filter(|revision| revision.group_id == group_id && revision.library_id == library_id)
        .max_by_key(|revision| revision.revision)
        .cloned()
}

async fn group_view(state: &AppState, group: &CompanyGroup) -> CompanyGroupView {
    let member_count = state
        .entities
        .read()
        .await
        .values()
        .filter(|entity| entity.tenant_id == group.tenant_id && entity.group_id == Some(group.id))
        .count();
    let template_library_count = state
        .group_template_libraries
        .read()
        .await
        .values()
        .filter(|library| library.group_id == group.id && !library.is_archived())
        .count();
    CompanyGroupView {
        group: group.clone(),
        member_count,
        template_library_count,
    }
}

async fn library_view(
    state: &AppState,
    library: &GroupTemplateLibrary,
) -> GroupTemplateLibraryView {
    let current_revision = current_revision(
        &*state.group_template_library_revisions.read().await,
        library.group_id,
        library.id,
    );
    GroupTemplateLibraryView {
        library: library.clone(),
        current_revision,
    }
}

async fn normalize_template_ids(
    state: &AppState,
    raw: Vec<String>,
) -> Result<Vec<String>, ApiError> {
    if raw.len() > MAX_LIBRARY_TEMPLATE_IDS {
        return Err(ApiError::Unprocessable(format!(
            "a template library revision may reference at most {MAX_LIBRARY_TEMPLATE_IDS} templates"
        )));
    }
    // wp28: the validate+dedupe+existence loop reads `user_template` per reference. Fold the WHOLE
    // loop into one blocking offload so those durable reads never run on a tokio worker; the
    // sequential logic (and its first-failure ordering) is preserved verbatim. With no durable
    // store the existence check is registry-only and hits no backend, so run it inline.
    match state.store.clone() {
        Some(store) => {
            store
                .read_blocking_async(move |s| normalize_template_ids_inner(raw, Some(s)))
                .await
        }
        None => normalize_template_ids_inner(raw, None),
    }
}

fn normalize_template_ids_inner(
    raw: Vec<String>,
    store: Option<&chancela_store::Store>,
) -> Result<Vec<String>, ApiError> {
    let mut seen = HashSet::new();
    let mut ids = Vec::with_capacity(raw.len());
    for id in raw {
        let id = normalized_required(id, "template_id", 240)?;
        if !seen.insert(id.clone()) {
            return Err(ApiError::Unprocessable(format!(
                "duplicate template reference `{id}`"
            )));
        }
        if !crate::documents::template_id_exists_in(store, &id)? {
            return Err(ApiError::Unprocessable(format!(
                "unknown template reference `{id}`"
            )));
        }
        ids.push(id);
    }
    ids.sort();
    Ok(ids)
}

/// List active groups in one tenant.
pub(crate) async fn list_groups(
    State(state): State<AppState>,
    Path(tenant): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<Vec<CompanyGroupView>>, ApiError> {
    let tenant_id = tenant_id(tenant);
    require_tenant(&state, &actor, Permission::EntityRead, tenant_id).await?;
    require_known_tenant(&state, tenant_id).await?;
    let mut groups = state
        .company_groups
        .read()
        .await
        .values()
        .filter(|group| group.tenant_id == tenant_id && !group.is_archived())
        .cloned()
        .collect::<Vec<_>>();
    groups.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    let mut views = Vec::with_capacity(groups.len());
    for group in &groups {
        views.push(group_view(&state, group).await);
    }
    Ok(Json(views))
}

pub(crate) async fn create_group(
    State(state): State<AppState>,
    Path(tenant): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<CreateGroupBody>,
) -> Result<(StatusCode, Json<CompanyGroupView>), ApiError> {
    let tenant_id = tenant_id(tenant);
    require_tenant(&state, &actor, Permission::EntityCreate, tenant_id).await?;
    require_known_tenant(&state, tenant_id).await?;
    let now = OffsetDateTime::now_utc();
    let mut group = CompanyGroup::new(
        tenant_id,
        normalized_required(body.name, "name", MAX_NAME_CHARS)?,
        now,
    );
    group.description = normalized_optional(body.description, "description")?;
    let payload = serde_json::to_vec(&group)?;
    let actor_name = actor.resolve("api");
    let scope = tenant_scope(tenant_id);
    let object = audit_object(group.id, None);

    let mut groups = state.company_groups.write().await;
    ensure_unique_group_name(&groups, tenant_id, None, &group.name)?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "company_group.created",
        Some(&object),
        &payload,
    )?;
    let group_for_store = group.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_company_group(&group_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    groups.insert(group.id, group.clone());
    drop(ledger);
    drop(groups);
    Ok((StatusCode::CREATED, Json(group_view(&state, &group).await)))
}

pub(crate) async fn get_group(
    State(state): State<AppState>,
    Path((tenant, group)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<CompanyGroupView>, ApiError> {
    let tenant_id = tenant_id(tenant);
    require_tenant(&state, &actor, Permission::EntityRead, tenant_id).await?;
    let group = group_for_path(
        &*state.company_groups.read().await,
        tenant_id,
        group_id(group),
    )?
    .clone();
    Ok(Json(group_view(&state, &group).await))
}

pub(crate) async fn patch_group(
    State(state): State<AppState>,
    Path((tenant, group)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<PatchGroupBody>,
) -> Result<Json<CompanyGroupView>, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    require_tenant(&state, &actor, Permission::EntityUpdate, tenant_id).await?;
    let actor_name = actor.resolve("api");
    let mut groups = state.company_groups.write().await;
    let current = group_for_path(&groups, tenant_id, group_id)?;
    if current.is_archived() {
        return Err(ApiError::Conflict(
            "archived groups cannot be edited".to_owned(),
        ));
    }
    let mut next = current.clone();
    if let Some(name) = body.name {
        next.name = normalized_required(name, "name", MAX_NAME_CHARS)?;
    }
    if let Some(description) = body.description {
        next.description = normalized_optional(description, "description")?;
    }
    ensure_unique_group_name(&groups, tenant_id, Some(group_id), &next.name)?;
    if next == *current {
        drop(groups);
        return Ok(Json(group_view(&state, &next).await));
    }
    next.updated_at = OffsetDateTime::now_utc();
    let payload = serde_json::to_vec(&next)?;
    let scope = tenant_scope(tenant_id);
    let object = audit_object(group_id, None);
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "company_group.updated",
        Some(&object),
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_company_group(&next_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    groups.insert(group_id, next.clone());
    drop(ledger);
    drop(groups);
    Ok(Json(group_view(&state, &next).await))
}

/// Soft-archive an empty group. Active libraries are archived in the same transaction while every
/// immutable revision remains intact. A caller must explicitly remove all members first.
pub(crate) async fn archive_group(
    State(state): State<AppState>,
    Path((tenant, group)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<StatusCode, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    require_tenant(&state, &actor, Permission::EntityUpdate, tenant_id).await?;
    let actor_name = actor.resolve("api");
    let mut groups = state.company_groups.write().await;
    let current = group_for_path(&groups, tenant_id, group_id)?;
    if current.is_archived() {
        return Ok(StatusCode::NO_CONTENT);
    }
    let mut libraries = state.group_template_libraries.write().await;
    let entities = state.entities.read().await;
    if entities
        .values()
        .any(|entity| entity.tenant_id == tenant_id && entity.group_id == Some(group_id))
    {
        return Err(ApiError::Conflict(
            "remove every entity from the group before archiving it".to_owned(),
        ));
    }
    let now = OffsetDateTime::now_utc();
    let mut next = current.clone();
    next.archived_at = Some(now);
    next.updated_at = now;
    let mut archived_libraries = Vec::new();
    for library in libraries
        .values()
        .filter(|library| library.group_id == group_id && !library.is_archived())
    {
        let mut archived = library.clone();
        archived.archived_at = Some(now);
        archived.updated_at = now;
        archived_libraries.push(archived);
    }
    drop(entities);
    let payload = serde_json::to_vec(&serde_json::json!({
        "group": &next,
        "archived_template_library_ids": archived_libraries
            .iter()
            .map(|library| library.id.to_string())
            .collect::<Vec<_>>(),
    }))?;
    let scope = tenant_scope(tenant_id);
    let object = audit_object(group_id, None);
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "company_group.archived",
        Some(&object),
        &payload,
    )?;
    let next_for_store = next.clone();
    let archived_libraries_for_store = archived_libraries.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_company_group(&next_for_store)?;
            for library in &archived_libraries_for_store {
                tx.upsert_group_template_library(library)?;
            }
            Ok(())
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    groups.insert(group_id, next);
    for library in archived_libraries {
        libraries.insert(library.id, library);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn assigned_entity(group: &CompanyGroup, entity: &Entity) -> Result<Entity, ApiError> {
    if group.is_archived() {
        return Err(ApiError::Conflict(
            "cannot assign entities to an archived group".to_owned(),
        ));
    }
    if !group.can_contain(entity) {
        return Err(ApiError::Conflict(
            "entity and group must belong to the same tenant".to_owned(),
        ));
    }
    if entity.group_id.is_some() && entity.group_id != Some(group.id) {
        return Err(ApiError::Conflict(
            "entity already belongs to another group; remove it first".to_owned(),
        ));
    }
    Ok(entity.clone().in_group(Some(group.id)))
}

pub(crate) async fn assign_entity(
    State(state): State<AppState>,
    Path((tenant, group, entity)): Path<(Uuid, Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<EntityView>, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    let entity_id = EntityId(entity);
    require_tenant(&state, &actor, Permission::EntityUpdate, tenant_id).await?;
    require_permission(
        &state,
        &actor,
        Permission::EntityUpdate,
        scope_of_entity(entity_id),
    )
    .await?;
    let groups = state.company_groups.read().await;
    let group = group_for_path(&groups, tenant_id, group_id)?;
    let mut entities = state.entities.write().await;
    let current = entities.get(&entity_id).ok_or(ApiError::NotFound)?;
    let next = assigned_entity(group, current)?;
    if next == *current {
        return Ok(Json(EntityView::from(current)));
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "entity_id": entity_id,
        "group_id": group_id,
        "tenant_id": tenant_id,
    }))?;
    let actor_name = actor.resolve("api");
    let scope = entity_ledger_scope(tenant_id, entity_id);
    let object = audit_object(group_id, None);
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "company_group.entity_assigned",
        Some(&object),
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_entity(&next_for_store))
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    entities.insert(entity_id, next.clone());
    Ok(Json(EntityView::from(&next)))
}

pub(crate) async fn remove_entity(
    State(state): State<AppState>,
    Path((tenant, group, entity)): Path<(Uuid, Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<EntityView>, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    let entity_id = EntityId(entity);
    require_tenant(&state, &actor, Permission::EntityUpdate, tenant_id).await?;
    require_permission(
        &state,
        &actor,
        Permission::EntityUpdate,
        scope_of_entity(entity_id),
    )
    .await?;
    let groups = state.company_groups.read().await;
    group_for_path(&groups, tenant_id, group_id)?;
    let mut entities = state.entities.write().await;
    let current = entities.get(&entity_id).ok_or(ApiError::NotFound)?;
    if current.tenant_id != tenant_id || current.group_id != Some(group_id) {
        return Err(ApiError::Conflict(
            "entity is not a member of this group".to_owned(),
        ));
    }
    let next = current.clone().in_group(None);
    let payload = serde_json::to_vec(&serde_json::json!({
        "entity_id": entity_id,
        "group_id": group_id,
        "tenant_id": tenant_id,
    }))?;
    let actor_name = actor.resolve("api");
    let scope = entity_ledger_scope(tenant_id, entity_id);
    let object = audit_object(group_id, None);
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "company_group.entity_removed",
        Some(&object),
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_entity(&next_for_store))
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    entities.insert(entity_id, next.clone());
    Ok(Json(EntityView::from(&next)))
}

pub(crate) async fn list_template_libraries(
    State(state): State<AppState>,
    Path((tenant, group)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<Vec<GroupTemplateLibraryView>>, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    require_tenant(&state, &actor, Permission::ActRead, tenant_id).await?;
    group_for_path(&*state.company_groups.read().await, tenant_id, group_id)?;
    let mut libraries = state
        .group_template_libraries
        .read()
        .await
        .values()
        .filter(|library| library.group_id == group_id && !library.is_archived())
        .cloned()
        .collect::<Vec<_>>();
    libraries.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    let mut views = Vec::with_capacity(libraries.len());
    for library in &libraries {
        views.push(library_view(&state, library).await);
    }
    Ok(Json(views))
}

pub(crate) async fn create_template_library(
    State(state): State<AppState>,
    Path((tenant, group)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<CreateTemplateLibraryBody>,
) -> Result<(StatusCode, Json<GroupTemplateLibraryView>), ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    require_tenant(&state, &actor, Permission::TemplateManage, tenant_id).await?;
    let template_ids = normalize_template_ids(&state, body.template_ids).await?;
    let groups = state.company_groups.read().await;
    let group = group_for_path(&groups, tenant_id, group_id)?;
    if group.is_archived() {
        return Err(ApiError::Conflict(
            "cannot create a library in an archived group".to_owned(),
        ));
    }
    let now = OffsetDateTime::now_utc();
    let mut library = GroupTemplateLibrary::new(
        group,
        normalized_required(body.name, "name", MAX_NAME_CHARS)?,
        now,
    );
    library.description = normalized_optional(body.description, "description")?;
    let actor_name = actor.resolve("api");
    let revision = GroupTemplateLibraryRevision {
        group_id,
        library_id: library.id,
        tenant_id,
        revision: 1,
        template_ids,
        created_at: now,
        created_by: actor_name.clone(),
    };
    let payload = serde_json::to_vec(&serde_json::json!({
        "library": &library,
        "revision": &revision,
    }))?;
    let scope = tenant_scope(tenant_id);
    let object = audit_object(group_id, Some(library.id));
    let mut libraries = state.group_template_libraries.write().await;
    ensure_unique_library_name(&libraries, group_id, None, &library.name)?;
    let mut revisions = state.group_template_library_revisions.write().await;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "group_template_library.created",
        Some(&object),
        &payload,
    )?;
    let library_for_store = library.clone();
    let revision_for_store = revision.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_group_template_library(&library_for_store)?;
            tx.insert_group_template_library_revision(&revision_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    libraries.insert(library.id, library.clone());
    revisions.insert((group_id, library.id, 1), revision.clone());
    Ok((
        StatusCode::CREATED,
        Json(GroupTemplateLibraryView {
            library,
            current_revision: Some(revision),
        }),
    ))
}

pub(crate) async fn get_template_library(
    State(state): State<AppState>,
    Path((tenant, group, library)): Path<(Uuid, Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<GroupTemplateLibraryView>, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    let library_id = library_id(library);
    require_permission(
        &state,
        &actor,
        Permission::ActRead,
        scope_of_template_library(library_id),
    )
    .await?;
    group_for_path(&*state.company_groups.read().await, tenant_id, group_id)?;
    let library = library_for_path(
        &*state.group_template_libraries.read().await,
        tenant_id,
        group_id,
        library_id,
    )?
    .clone();
    Ok(Json(library_view(&state, &library).await))
}

pub(crate) async fn patch_template_library(
    State(state): State<AppState>,
    Path((tenant, group, library)): Path<(Uuid, Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<PatchTemplateLibraryBody>,
) -> Result<Json<GroupTemplateLibraryView>, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    let library_id = library_id(library);
    require_permission(
        &state,
        &actor,
        Permission::TemplateManage,
        scope_of_template_library(library_id),
    )
    .await?;
    let groups = state.company_groups.read().await;
    let group = group_for_path(&groups, tenant_id, group_id)?;
    if group.is_archived() {
        return Err(ApiError::Conflict(
            "archived groups cannot be edited".to_owned(),
        ));
    }
    let mut libraries = state.group_template_libraries.write().await;
    let current = library_for_path(&libraries, tenant_id, group_id, library_id)?;
    if current.is_archived() {
        return Err(ApiError::Conflict(
            "archived template libraries cannot be edited".to_owned(),
        ));
    }
    let mut next = current.clone();
    if let Some(name) = body.name {
        next.name = normalized_required(name, "name", MAX_NAME_CHARS)?;
    }
    if let Some(description) = body.description {
        next.description = normalized_optional(description, "description")?;
    }
    ensure_unique_library_name(&libraries, group_id, Some(library_id), &next.name)?;
    if next == *current {
        drop(libraries);
        return Ok(Json(library_view(&state, &next).await));
    }
    next.updated_at = OffsetDateTime::now_utc();
    let payload = serde_json::to_vec(&next)?;
    let actor_name = actor.resolve("api");
    let scope = tenant_scope(tenant_id);
    let object = audit_object(group_id, Some(library_id));
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "group_template_library.updated",
        Some(&object),
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_group_template_library(&next_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    libraries.insert(library_id, next.clone());
    drop(ledger);
    drop(libraries);
    Ok(Json(library_view(&state, &next).await))
}

pub(crate) async fn archive_template_library(
    State(state): State<AppState>,
    Path((tenant, group, library)): Path<(Uuid, Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<StatusCode, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    let library_id = library_id(library);
    require_permission(
        &state,
        &actor,
        Permission::TemplateManage,
        scope_of_template_library(library_id),
    )
    .await?;
    let groups = state.company_groups.read().await;
    let group = group_for_path(&groups, tenant_id, group_id)?;
    if group.is_archived() {
        return Err(ApiError::Conflict(
            "cannot archive a library in an archived group".to_owned(),
        ));
    }
    let mut libraries = state.group_template_libraries.write().await;
    let current = library_for_path(&libraries, tenant_id, group_id, library_id)?;
    if current.is_archived() {
        return Ok(StatusCode::NO_CONTENT);
    }
    let now = OffsetDateTime::now_utc();
    let mut next = current.clone();
    next.archived_at = Some(now);
    next.updated_at = now;
    let payload = serde_json::to_vec(&next)?;
    let actor_name = actor.resolve("api");
    let scope = tenant_scope(tenant_id);
    let object = audit_object(group_id, Some(library_id));
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "group_template_library.archived",
        Some(&object),
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_group_template_library(&next_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    libraries.insert(library_id, next);
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn append_template_library_revision(
    State(state): State<AppState>,
    Path((tenant, group, library)): Path<(Uuid, Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<AppendTemplateLibraryRevisionBody>,
) -> Result<(StatusCode, Json<GroupTemplateLibraryRevision>), ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    let library_id = library_id(library);
    require_permission(
        &state,
        &actor,
        Permission::TemplateManage,
        scope_of_template_library(library_id),
    )
    .await?;
    let template_ids = normalize_template_ids(&state, body.template_ids).await?;
    let groups = state.company_groups.read().await;
    let group = group_for_path(&groups, tenant_id, group_id)?;
    if group.is_archived() {
        return Err(ApiError::Conflict(
            "cannot revise a library in an archived group".to_owned(),
        ));
    }
    let libraries = state.group_template_libraries.read().await;
    let library = library_for_path(&libraries, tenant_id, group_id, library_id)?;
    if library.is_archived() {
        return Err(ApiError::Conflict(
            "cannot revise an archived template library".to_owned(),
        ));
    }
    let mut revisions = state.group_template_library_revisions.write().await;
    let previous = current_revision(&revisions, group_id, library_id)
        .ok_or_else(|| ApiError::Conflict("template library has no initial revision".to_owned()))?;
    if previous.template_ids == template_ids {
        return Err(ApiError::Conflict(
            "new template library revision is identical to the current revision".to_owned(),
        ));
    }
    let actor_name = actor.resolve("api");
    let revision = GroupTemplateLibraryRevision {
        group_id,
        library_id,
        tenant_id,
        revision: previous.revision.checked_add(1).ok_or_else(|| {
            ApiError::Conflict("template library revision counter exhausted".to_owned())
        })?,
        template_ids,
        created_at: OffsetDateTime::now_utc(),
        created_by: actor_name.clone(),
    };
    let payload = serde_json::to_vec(&revision)?;
    let scope = tenant_scope(tenant_id);
    let object = audit_object(group_id, Some(library_id));
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "group_template_library.revision_created",
        Some(&object),
        &payload,
    )?;
    let revision_for_store = revision.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.insert_group_template_library_revision(&revision_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    revisions.insert((group_id, library_id, revision.revision), revision.clone());
    Ok((StatusCode::CREATED, Json(revision)))
}

pub(crate) async fn template_library_history(
    State(state): State<AppState>,
    Path((tenant, group, library)): Path<(Uuid, Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<Vec<GroupTemplateLibraryRevision>>, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    let library_id = library_id(library);
    require_permission(
        &state,
        &actor,
        Permission::ActRead,
        scope_of_template_library(library_id),
    )
    .await?;
    group_for_path(&*state.company_groups.read().await, tenant_id, group_id)?;
    library_for_path(
        &*state.group_template_libraries.read().await,
        tenant_id,
        group_id,
        library_id,
    )?;
    let mut history = state
        .group_template_library_revisions
        .read()
        .await
        .values()
        .filter(|revision| revision.group_id == group_id && revision.library_id == library_id)
        .cloned()
        .collect::<Vec<_>>();
    history.sort_by_key(|revision| revision.revision);
    Ok(Json(history))
}

pub(crate) async fn get_template_library_revision(
    State(state): State<AppState>,
    Path((tenant, group, library, revision)): Path<(Uuid, Uuid, Uuid, u64)>,
    actor: CurrentActor,
) -> Result<Json<GroupTemplateLibraryRevision>, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    let library_id = library_id(library);
    require_permission(
        &state,
        &actor,
        Permission::ActRead,
        scope_of_template_library(library_id),
    )
    .await?;
    group_for_path(&*state.company_groups.read().await, tenant_id, group_id)?;
    library_for_path(
        &*state.group_template_libraries.read().await,
        tenant_id,
        group_id,
        library_id,
    )?;
    state
        .group_template_library_revisions
        .read()
        .await
        .get(&(group_id, library_id, revision))
        .cloned()
        .map(Json)
        .ok_or(ApiError::NotFound)
}

fn book_state_name(state: BookState) -> String {
    match state {
        BookState::Created => "Created",
        BookState::Open => "Open",
        BookState::Closed => "Closed",
    }
    .to_owned()
}

fn act_state_name(state: ActState) -> String {
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
    .to_owned()
}

pub(crate) async fn group_dashboard(
    State(state): State<AppState>,
    Path((tenant, group)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<GroupDashboardView>, ApiError> {
    let tenant_id = tenant_id(tenant);
    let group_id = group_id(group);
    let authz = authorizer(&state, &actor).await?;
    let tenant_authz_scope = scope_of_tenant(tenant_id);
    authz.require(Permission::EntityRead, tenant_authz_scope)?;
    authz.require(Permission::BookRead, tenant_authz_scope)?;
    authz.require(Permission::ActRead, tenant_authz_scope)?;
    authz.require(Permission::LedgerRead, tenant_authz_scope)?;
    let group = group_for_path(&*state.company_groups.read().await, tenant_id, group_id)?.clone();
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let entities = state.entities.read().await;
    let mut member_entities = entities
        .values()
        .filter(|entity| entity.tenant_id == tenant_id && entity.group_id == Some(group_id))
        .filter(|entity| authz.permits(Permission::EntityRead, scope_of_entity(entity.id)))
        .collect::<Vec<_>>();
    member_entities.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.0.cmp(&b.id.0)));
    let entity_ids = member_entities
        .iter()
        .map(|entity| entity.id)
        .collect::<HashSet<_>>();
    let entity_views = member_entities
        .iter()
        .map(|entity| EntityView::build(entity, redaction))
        .collect::<Vec<_>>();

    let books = state.books.read().await;
    let member_books = books
        .values()
        .filter(|book| entity_ids.contains(&book.entity_id))
        .filter(|book| authz.permits(Permission::BookRead, scope_of_book(book.id)))
        .collect::<Vec<_>>();
    let book_ids = member_books
        .iter()
        .map(|book| book.id)
        .collect::<HashSet<_>>();
    let mut books_by_state = BTreeMap::new();
    for book in &member_books {
        *books_by_state
            .entry(book_state_name(book.state))
            .or_default() += 1;
    }
    let books_total = member_books.len();

    let acts = state.acts.read().await;
    let member_acts = acts
        .values()
        .filter(|act| book_ids.contains(&act.book_id))
        .filter(|act| authz.permits(Permission::ActRead, scope_of_book(act.book_id)))
        .collect::<Vec<_>>();
    let act_ids = member_acts.iter().map(|act| act.id).collect::<HashSet<_>>();
    let mut acts_by_state = BTreeMap::new();
    for act in &member_acts {
        *acts_by_state.entry(act_state_name(act.state)).or_default() += 1;
    }
    let acts_total = member_acts.len();

    let today = OffsetDateTime::now_utc().date();
    let follow_ups = state.follow_ups.read().await;
    let mut reminders = follow_ups
        .values()
        .filter(|follow_up| {
            act_ids.contains(&follow_up.act_id) && follow_up.status == StoredFollowUpStatus::Open
        })
        .map(|follow_up| GroupReminderView {
            id: follow_up.id.clone(),
            act_id: follow_up.act_id.to_string(),
            title: follow_up.title.clone(),
            due_date: follow_up.due_date.map(|date| date.to_string()),
            overdue: follow_up.due_date.is_some_and(|date| date < today),
            assignee: follow_up
                .assignee_display
                .clone()
                .or_else(|| follow_up.assignee.clone()),
        })
        .collect::<Vec<_>>();
    reminders.sort_by(|a, b| {
        a.due_date
            .cmp(&b.due_date)
            .then(a.title.cmp(&b.title))
            .then(a.id.cmp(&b.id))
    });
    let reminders_overdue = reminders.iter().filter(|reminder| reminder.overdue).count();

    let group_marker = audit_object(group_id, None);
    let entity_chain_ids = entity_ids
        .iter()
        .map(ToString::to_string)
        .collect::<HashSet<_>>();
    let book_chain_ids = book_ids
        .iter()
        .map(ToString::to_string)
        .collect::<HashSet<_>>();
    let tenant_event_scope = tenant_scope(tenant_id);
    let tenant_descendant_scope = format!("{tenant_event_scope}/");
    let ledger = state.ledger.read().await;
    let recent_audit_events = ledger
        .events()
        .iter()
        .rev()
        .filter(|event| {
            let tenant_scoped = event.scope == tenant_event_scope
                || event.scope.starts_with(&tenant_descendant_scope);
            let group_event = tenant_scoped
                && event
                    .justification
                    .as_deref()
                    .is_some_and(|value| value.starts_with(&group_marker));
            let member_event = event.links.iter().any(|link| match &link.chain {
                ChainId::Company(id) => entity_chain_ids.contains(id),
                ChainId::Book(id) => book_chain_ids.contains(id),
                _ => false,
            });
            group_event || member_event
        })
        .take(GROUP_AUDIT_EVENT_LIMIT)
        .map(LedgerEventView::from)
        .collect();

    drop(ledger);
    drop(follow_ups);
    drop(acts);
    drop(books);
    drop(entities);
    let view = GroupDashboardView {
        group: group_view(&state, &group).await,
        member_entities: entity_views,
        books_total,
        books_by_state,
        acts_total,
        acts_by_state,
        reminders_open: reminders.len(),
        reminders_overdue,
        reminders,
        recent_audit_events,
    };
    Ok(Json(view))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request};
    use chancela_authz::{
        GUEST_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId, Scope,
    };
    use chancela_core::{Act, Book, BookKind, EntityKind, MeetingChannel, Nipc, Tenant};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    fn entity(tenant_id: TenantId) -> Entity {
        Entity::new(
            "Encosto Estratégico, Lda.",
            Nipc::parse("503004642").unwrap(),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(tenant_id)
    }

    async fn send_raw(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
        let response = crate::router(state)
            .oneshot(request)
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("response body is JSON")
        };
        (status, body)
    }

    fn request(method: Method, uri: &str, body: Option<Value>, token: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-chancela-session", token);
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        builder.body(body).expect("request builds")
    }

    async fn token_for_role_at(
        state: &AppState,
        username: &str,
        role_id: RoleId,
        scope: Scope,
    ) -> String {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;

        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let user_id = UserId(Uuid::new_v4());
        state.users.write().await.insert(
            user_id,
            User {
                id: user_id,
                username: username.to_owned(),
                display_name: username.to_owned(),
                email: None,
                created_at: OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .unwrap_or_default(),
                active: true,
                password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
                attestation_key: None,
                secret_source: Default::default(),
                recovery_hash: None,
                role_assignments: vec![RoleAssignment::new(role_id, scope)],
            },
        );
        let token = Uuid::new_v4().to_string();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id,
                unlocked_key: None,
                expires_at: OffsetDateTime::now_utc()
                    + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    async fn install_tenants(state: &AppState) -> (Tenant, Tenant) {
        let tenant_a = Tenant::new("Tenant A");
        let tenant_b = Tenant::new("Tenant B");
        let mut tenants = state.tenants.write().await;
        tenants.insert(tenant_a.id, tenant_a.clone());
        tenants.insert(tenant_b.id, tenant_b.clone());
        (tenant_a, tenant_b)
    }

    #[test]
    fn membership_lifecycle_is_tenant_safe_and_refuses_implicit_moves() {
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let group_a = CompanyGroup::new(tenant_a, "A", OffsetDateTime::UNIX_EPOCH);
        let other_a = CompanyGroup::new(tenant_a, "A2", OffsetDateTime::UNIX_EPOCH);
        let group_b = CompanyGroup::new(tenant_b, "B", OffsetDateTime::UNIX_EPOCH);
        let original = entity(tenant_a);
        let assigned = assigned_entity(&group_a, &original).unwrap();
        assert_eq!(assigned.group_id, Some(group_a.id));
        assert!(assigned_entity(&group_b, &original).is_err());
        assert!(assigned_entity(&other_a, &assigned).is_err());
        assert_eq!(assigned.in_group(None).group_id, None);
    }

    #[test]
    fn membership_scope_joins_existing_tenant_and_company_chains() {
        let tenant_id = TenantId::new();
        let entity_id = EntityId::new();
        let memberships = chancela_ledger::Ledger::memberships(
            &entity_ledger_scope(tenant_id, entity_id),
            "company_group.entity_assigned",
        );
        assert!(memberships.contains(&ChainId::Tenant(tenant_id.to_string())));
        assert!(memberships.contains(&ChainId::Company(entity_id.to_string())));
    }

    #[tokio::test]
    async fn routes_enforce_tenant_membership_archive_and_active_name_invariants() {
        let state = AppState::default();
        let (tenant_a, tenant_b) = install_tenants(&state).await;
        let owner_a = token_for_role_at(
            &state,
            "owner.a",
            OWNER_ROLE_ID,
            scope_of_tenant(tenant_a.id),
        )
        .await;
        let entity_a = entity(tenant_a.id);
        let entity_b = entity(tenant_b.id);
        let entity_a_id = entity_a.id;
        let entity_b_id = entity_b.id;
        {
            let mut entities = state.entities.write().await;
            entities.insert(entity_a_id, entity_a);
            entities.insert(entity_b_id, entity_b);
        }
        state.ledger.write().await.append(
            "fixture",
            &entity_a_id.to_string(),
            "entity.created",
            None,
            b"{}",
        );

        let groups_uri = format!("/v1/tenants/{}/groups", tenant_a.id);
        let (status, created) = send_raw(
            state.clone(),
            request(
                Method::POST,
                &groups_uri,
                Some(json!({"name": "Grupo Encosto", "description": "Empresas A"})),
                &owner_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let group_id = created["id"].as_str().expect("group id");

        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::POST,
                &groups_uri,
                Some(json!({"name": "  grupo encosto  "})),
                &owner_a,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "active group names are unique case-insensitively within a tenant"
        );

        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::GET,
                &format!("/v1/tenants/{}/groups", tenant_b.id),
                None,
                &owner_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let membership_uri = format!(
            "/v1/tenants/{}/groups/{group_id}/entities/{entity_a_id}",
            tenant_a.id
        );
        let (status, assigned) = send_raw(
            state.clone(),
            request(Method::PUT, &membership_uri, None, &owner_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{assigned}");
        assert_eq!(assigned["group_id"], group_id);

        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::PUT,
                &format!(
                    "/v1/tenants/{}/groups/{group_id}/entities/{entity_b_id}",
                    tenant_a.id
                ),
                None,
                &owner_a,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "cross-tenant entity is not enumerable"
        );

        let group_uri = format!("/v1/tenants/{}/groups/{group_id}", tenant_a.id);
        let (status, _) = send_raw(
            state.clone(),
            request(Method::DELETE, &group_uri, None, &owner_a),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a group with members cannot be archived"
        );

        let (status, removed) = send_raw(
            state.clone(),
            request(Method::DELETE, &membership_uri, None, &owner_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{removed}");
        assert!(removed["group_id"].is_null());

        let (status, _) = send_raw(
            state.clone(),
            request(Method::DELETE, &group_uri, None, &owner_a),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::PATCH,
                &group_uri,
                Some(json!({"name": "Resurrected"})),
                &owner_a,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "archived groups are immutable"
        );
        let (status, _) =
            send_raw(state, request(Method::PUT, &membership_uri, None, &owner_a)).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "archived groups cannot accept members"
        );
    }

    /// wp27-e3 (Part 1): the group dashboard is a tenant-reachable scan surface. A tenant-A owner
    /// sees only tenant-A members on A's dashboard and gets a non-enumerating `403` on tenant-B's
    /// dashboard — freezing the `require ... @ scope_of_tenant` gate + the `tenant_id ==` filter
    /// against a cross-tenant leak regression.
    #[tokio::test]
    async fn group_dashboard_is_tenant_scoped_and_refuses_cross_tenant() {
        let state = AppState::default();
        let (tenant_a, tenant_b) = install_tenants(&state).await;
        let owner_a = token_for_role_at(
            &state,
            "owner.a",
            OWNER_ROLE_ID,
            scope_of_tenant(tenant_a.id),
        )
        .await;

        let group_a = CompanyGroup::new(tenant_a.id, "Grupo A", OffsetDateTime::UNIX_EPOCH);
        let group_b = CompanyGroup::new(tenant_b.id, "Grupo B", OffsetDateTime::UNIX_EPOCH);
        let member_a = assigned_entity(&group_a, &entity(tenant_a.id)).expect("assign A member");
        let member_a_id = member_a.id;
        {
            let mut groups = state.company_groups.write().await;
            groups.insert(group_a.id, group_a.clone());
            groups.insert(group_b.id, group_b.clone());
            state.entities.write().await.insert(member_a_id, member_a);
        }

        // A's dashboard shows only A's member.
        let (status, dash) = send_raw(
            state.clone(),
            request(
                Method::GET,
                &format!(
                    "/v1/tenants/{}/groups/{}/dashboard",
                    tenant_a.id, group_a.id
                ),
                None,
                &owner_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{dash}");
        let members = dash["member_entities"].as_array().expect("members");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0]["id"], member_a_id.to_string());

        // B's dashboard is a non-enumerating 403 for the tenant-A owner.
        let (status, _) = send_raw(
            state,
            request(
                Method::GET,
                &format!(
                    "/v1/tenants/{}/groups/{}/dashboard",
                    tenant_b.id, group_b.id
                ),
                None,
                &owner_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn template_library_routes_validate_references_and_preserve_immutable_history() {
        let state = AppState::default();
        let (tenant, _) = install_tenants(&state).await;
        let owner = token_for_role_at(&state, "owner", OWNER_ROLE_ID, Scope::Global).await;
        let group = CompanyGroup::new(tenant.id, "Grupo", OffsetDateTime::UNIX_EPOCH);
        state
            .company_groups
            .write()
            .await
            .insert(group.id, group.clone());
        let libraries_uri = format!(
            "/v1/tenants/{}/groups/{}/template-libraries",
            tenant.id, group.id
        );

        let (status, unknown) = send_raw(
            state.clone(),
            request(
                Method::POST,
                &libraries_uri,
                Some(json!({"name": "Invalid", "template_ids": ["missing/v1"]})),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{unknown}");

        let (status, created) = send_raw(
            state.clone(),
            request(
                Method::POST,
                &libraries_uri,
                Some(json!({
                    "name": "Atas comuns",
                    "template_ids": ["csc-ata-ag/v1"]
                })),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["current_revision"]["revision"], 1);
        let library_id = created["id"].as_str().expect("library id");

        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::POST,
                &libraries_uri,
                Some(json!({"name": "ATAS COMUNS", "template_ids": []})),
                &owner,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "active library names are unique case-insensitively within a group"
        );

        let library_uri = format!("{libraries_uri}/{library_id}");
        let revisions_uri = format!("{library_uri}/revisions");
        let (status, revision_two) = send_raw(
            state.clone(),
            request(
                Method::POST,
                &revisions_uri,
                Some(json!({
                    "template_ids": ["csc-convocatoria-ag/v1", "csc-ata-ag/v1"]
                })),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{revision_two}");
        assert_eq!(revision_two["revision"], 2);

        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::POST,
                &revisions_uri,
                Some(json!({
                    "template_ids": ["csc-ata-ag/v1", "csc-convocatoria-ag/v1"]
                })),
                &owner,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "identical revisions are refused"
        );

        let (status, history) = send_raw(
            state.clone(),
            request(Method::GET, &format!("{library_uri}/history"), None, &owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{history}");
        assert_eq!(history.as_array().expect("history array").len(), 2);
        assert_eq!(history[0]["revision"], 1);
        assert_eq!(history[1]["revision"], 2);

        let (status, revision_one) = send_raw(
            state.clone(),
            request(Method::GET, &format!("{revisions_uri}/1"), None, &owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{revision_one}");
        assert_eq!(revision_one["template_ids"], json!(["csc-ata-ag/v1"]));

        let (status, _) = send_raw(
            state.clone(),
            request(Method::DELETE, &library_uri, None, &owner),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::POST,
                &revisions_uri,
                Some(json!({"template_ids": []})),
                &owner,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "archived libraries cannot be revised"
        );

        let (status, preserved) = send_raw(
            state,
            request(Method::GET, &format!("{library_uri}/history"), None, &owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{preserved}");
        assert_eq!(preserved.as_array().expect("history array").len(), 2);
    }

    #[tokio::test]
    async fn dashboard_is_tenant_safe_rbac_gated_and_filters_members_and_audit_events() {
        let state = AppState::default();
        let (tenant_a, tenant_b) = install_tenants(&state).await;
        let group = CompanyGroup::new(tenant_a.id, "Grupo A", OffsetDateTime::UNIX_EPOCH);
        state
            .company_groups
            .write()
            .await
            .insert(group.id, group.clone());

        let member = entity(tenant_a.id).in_group(Some(group.id));
        let non_member = Entity::new(
            "Fora do Grupo, Lda.",
            Nipc::unvalidated("OUTSIDE-1"),
            "Porto",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(tenant_a.id);
        let malicious_cross_tenant = Entity::new(
            "Outro Tenant, Lda.",
            Nipc::unvalidated("TENANT-B-1"),
            "Braga",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(tenant_b.id)
        .in_group(Some(group.id));
        let member_id = member.id;
        let non_member_id = non_member.id;
        let cross_tenant_id = malicious_cross_tenant.id;
        {
            let mut entities = state.entities.write().await;
            entities.insert(member_id, member);
            entities.insert(non_member_id, non_member);
            entities.insert(cross_tenant_id, malicious_cross_tenant);
        }
        let member_book = Book::new(member_id, BookKind::AssembleiaGeral);
        let non_member_book = Book::new(non_member_id, BookKind::AssembleiaGeral);
        let cross_tenant_book = Book::new(cross_tenant_id, BookKind::AssembleiaGeral);
        let member_book_id = member_book.id;
        {
            let mut books = state.books.write().await;
            books.insert(member_book.id, member_book);
            books.insert(non_member_book.id, non_member_book);
            books.insert(cross_tenant_book.id, cross_tenant_book);
        }
        let member_act = Act::draft(member_book_id, "Ata membro", MeetingChannel::Physical);
        state.acts.write().await.insert(member_act.id, member_act);

        {
            let mut ledger = state.ledger.write().await;
            let marker = audit_object(group.id, None);
            ledger.append(
                "owner.a",
                &tenant_scope(tenant_a.id),
                "company_group.updated",
                Some(&marker),
                b"{}",
            );
            ledger.append(
                "owner.b",
                &tenant_scope(tenant_b.id),
                "company_group.updated",
                Some(&marker),
                b"{}",
            );
            ledger.append(
                "owner.a",
                &entity_ledger_scope(tenant_a.id, member_id),
                "entity.updated",
                None,
                b"{}",
            );
            ledger.append(
                "owner.a",
                &entity_ledger_scope(tenant_a.id, non_member_id),
                "entity.updated",
                None,
                b"{}",
            );
            // Pre-tenancy entity/book events remain on their canonical company chain even though
            // their scope string has no tenant segment; the dashboard must retain that history.
            ledger.append(
                "legacy",
                &member_id.to_string(),
                "entity.updated",
                None,
                b"{}",
            );
        }

        let owner_a = token_for_role_at(
            &state,
            "owner.a",
            OWNER_ROLE_ID,
            scope_of_tenant(tenant_a.id),
        )
        .await;
        let dashboard_uri = format!("/v1/tenants/{}/groups/{}/dashboard", tenant_a.id, group.id);
        let (status, dashboard) = send_raw(
            state.clone(),
            request(Method::GET, &dashboard_uri, None, &owner_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{dashboard}");
        assert_eq!(dashboard["member_entities"].as_array().unwrap().len(), 1);
        assert_eq!(dashboard["member_entities"][0]["id"], member_id.to_string());
        assert_eq!(dashboard["books_total"], 1);
        assert_eq!(dashboard["acts_total"], 1);
        let audit = dashboard["recent_audit_events"].as_array().unwrap();
        assert_eq!(audit.len(), 3, "only this group/member events are visible");
        let audit_json = serde_json::to_string(audit).unwrap();
        assert!(audit_json.contains(&member_id.to_string()));
        assert!(audit_json.contains(&tenant_scope(tenant_a.id)));
        assert!(!audit_json.contains(&tenant_scope(tenant_b.id)));
        assert!(!audit_json.contains(&non_member_id.to_string()));

        let owner_b = token_for_role_at(
            &state,
            "owner.b",
            OWNER_ROLE_ID,
            scope_of_tenant(tenant_b.id),
        )
        .await;
        let (status, _) = send_raw(
            state.clone(),
            request(Method::GET, &dashboard_uri, None, &owner_b),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let guest_a = token_for_role_at(
            &state,
            "guest.a",
            GUEST_ROLE_ID,
            scope_of_tenant(tenant_a.id),
        )
        .await;
        let (status, _) =
            send_raw(state, request(Method::GET, &dashboard_uri, None, &guest_a)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a guest without ledger.read never receives an unredacted audit dashboard"
        );
    }
}
