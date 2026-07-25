//! Entity endpoints (contract §2.3) — unchanged from the scaffold, moved here for the
//! module split. Entities are the root object: books belong to an entity, acts to a book.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chancela_authz::{Permission, Scope};
use chancela_core::{
    Book, BookId, BookKind, BookState, ClosingReason, DEFAULT_TENANT_ID, DocumentLayoutOverrides,
    Entity, EntityFamily, EntityId, EntityKind, Nipc, StatuteOverrides, TenantId,
    resolve_document_layout,
};
use chancela_ledger::{ChainId, Event};
use serde::Deserialize;
use time::{Date, Month};
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{
    authorizer, require_permission, scope_of_book, scope_of_entity, scope_of_tenant,
};
use crate::collection_page::{
    CollectionPage, CollectionPageQuery, CursorPosition, apply_keyset, fold_search,
    query_fingerprint,
};
use crate::dto::{
    BookStateCountsView, BookView, EntityActivitySummaryView, EntityListItemView,
    EntityRegistrySummaryView, EntityView, LedgerEventView, compute_expired,
    read_redaction_for_actor,
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
    /// The tenant to create the entity in (wp27 tenancy P4). Absent (the common single-tenant case)
    /// the singleton [`DEFAULT_TENANT_ID`] is used, so single-tenant callers never name a tenant and
    /// behaviour is byte-identical to before tenancy. When present it must name a known tenant the
    /// caller is authorized to create in (see [`create_entity`]).
    #[serde(default)]
    tenant_id: Option<Uuid>,
}

/// Create an entity, record an `entity.created` ledger event, and return it with `201`.
pub async fn create_entity(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateEntity>,
) -> Result<(StatusCode, Json<EntityView>), ApiError> {
    // Tenancy (wp27-e1): the entity is created **inside a tenant**. Absent an explicit `tenant_id`
    // the singleton default tenant is used, so single-tenant deployments stay byte-identical.
    // Authorization narrows to that tenant (it was `Global`): a Global holder still covers every
    // tenant, while a tenant-scoped holder may only create within its own tenant — the cross-tenant
    // write guard. The verb stays `EntityCreate`; only the tenant CRUD verbs change under e2.
    let tenant_id = req.tenant_id.map_or(DEFAULT_TENANT_ID, TenantId);
    require_permission(
        &state,
        &actor,
        Permission::EntityCreate,
        scope_of_tenant(tenant_id),
    )
    .await?;
    // An explicitly-named tenant must exist — a `404` **after** the authz check above (so a caller
    // outside the tenant already got a non-enumerating `403` and never learns whether it exists). The
    // implicit default tenant is always present, so a body without `tenant_id` skips this check and
    // never regresses the single-tenant path (where `AppState` may hold no tenant directory yet).
    if req.tenant_id.is_some() && !state.tenants.read().await.contains_key(&tenant_id) {
        return Err(ApiError::NotFound);
    }
    // A parseable NIPC is always stored validated; the override only rescues a parse failure.
    let nipc = match Nipc::parse(&req.nipc) {
        Ok(nipc) => nipc,
        Err(_) if req.allow_invalid_nipc => Nipc::unvalidated(&req.nipc),
        Err(e) => return Err(e.into()),
    };
    let overridden = !nipc.is_validated();
    let fiscal_year_end = normalize_fiscal_year_end(req.fiscal_year_end)?;
    let mut entity = Entity::new(req.name, nipc, req.seat, req.kind).in_tenant(tenant_id);
    entity.fiscal_year_end = fiscal_year_end;

    // Digest the created entity into the audit chain before it becomes queryable, so the
    // ledger is the source of truth for "what happened" (DAT-10). The entity's own serialization
    // already carries `nipc.validated: false` for an override; the justification makes the
    // deliberate skip explicit and greppable in the audit trail.
    let payload = serde_json::to_vec(&entity)?;
    let justification = overridden.then_some(NIPC_OVERRIDE_JUSTIFICATION);
    let actor = actor.resolve("api");
    // Emit the entity genesis on its `tenant:{t}/entity:{id}` scope so the write joins BOTH its tenant
    // chain (ChainId::Tenant — previously missing on entity mutations, a1 Q1) and its company chain.
    // The `company:`-equivalent `entity:` segment keeps `entity.created` the genesis of the company
    // chain (unchanged), while the added `tenant:` segment additively links the per-tenant chain.
    let scope = format!("tenant:{tenant_id}/entity:{}", entity.id);
    {
        // Append the event and, when persistent, durably write the event + the new entity row in
        // one transaction. A store failure rolls back the append and returns 500 without mutating
        // the read model (below), so memory and disk never diverge.
        let mut ledger = state.ledger.write().await;
        ledger.append(&actor, &scope, "entity.created", justification, &payload);
        let entity_for_store = entity.clone();
        state
            .persist_write_through(&mut ledger, 1, move |tx| {
                tx.upsert_entity(&entity_for_store)
            })
            .await?;
        state.attest_latest(&attestor, &ledger).await;
    }

    let view = EntityView::from(&entity);
    state.entities.write().await.insert(entity.id, entity);
    Ok((StatusCode::CREATED, Json(view)))
}

/// Justification recorded on the `entity.statute_updated` event (ENT-03 audit trail). Frozen
/// wording so a statute-overlay edit is greppable in the ledger.
const STATUTE_UPDATE_JUSTIFICATION: &str = "entity statute overlay updated";
const LAYOUT_SET_JUSTIFICATION: &str = "entity document layout override set";
const LAYOUT_CLEAR_JUSTIFICATION: &str = "entity document layout override cleared";

/// Request body for `PATCH /v1/entities/{id}`. Currently the statute overlay only (ENT-03); the
/// body is extendable. Uses [`double_option`](crate::dto::double_option) so an absent key leaves
/// the overlay untouched, an explicit `null` clears it, and an object sets it.
#[derive(Deserialize)]
pub struct PatchEntity {
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    statute: Option<Option<StatuteOverrides>>,
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    fiscal_year_end: Option<Option<String>>,
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    document_layout_override: Option<Option<DocumentLayoutOverrides>>,
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
    let instance_layout = state
        .settings
        .read()
        .await
        .documents
        .layout_defaults
        .clone();
    // entities → ledger (the global lock order); attestation sidecar acquired last.
    let mut entities = state.entities.write().await;
    let books = state.books.read().await;

    let entity = entities.get_mut(&EntityId(id)).ok_or(ApiError::NotFound)?;

    // Apply to a clone so the in-memory map is mutated only after the durable write commits (a
    // store failure rolls back the appended event and leaves the entity untouched).
    let mut next = entity.clone();
    let statute_changed = req.statute.is_some();
    let fiscal_year_end_changed = req.fiscal_year_end.is_some();
    let layout_changed = req.document_layout_override.is_some();
    if !statute_changed && !fiscal_year_end_changed && !layout_changed {
        return Ok(Json(EntityView::from(&*entity)));
    }
    if let Some(statute) = req.statute {
        next.statute = statute;
    }
    if let Some(fiscal_year_end) = req.fiscal_year_end {
        next.fiscal_year_end = normalize_fiscal_year_end(fiscal_year_end)?;
    }
    if let Some(document_layout_override) = req.document_layout_override {
        next.document_layout_override =
            crate::dto::normalize_document_layout_override(document_layout_override);
        let mut found_book = false;
        for book in books.values().filter(|book| book.entity_id == next.id) {
            found_book = true;
            resolve_document_layout(
                &instance_layout,
                None,
                next.document_layout_override.as_ref(),
                book.document_layout_override.as_ref(),
            )
            .map_err(|error| {
                ApiError::Unprocessable(format!(
                    "invalid document_layout_override for book {}: {error}",
                    book.id
                ))
            })?;
        }
        if !found_book {
            resolve_document_layout(
                &instance_layout,
                None,
                next.document_layout_override.as_ref(),
                None,
            )
            .map_err(|error| {
                ApiError::Unprocessable(format!("invalid document_layout_override: {error}"))
            })?;
        }
    }

    let entity_scope = next.id.to_string();
    let layout_scope = format!("tenant:{}/entity:{}", next.tenant_id, next.id);
    let entity_payload = serde_json::to_vec(&next)?;
    let mut ledger = state.ledger.write().await;
    let mut appended = 0;
    if layout_changed {
        let layout_payload = serde_json::to_vec(&serde_json::json!({
            "entity_id": next.id,
            "document_layout_override": next.document_layout_override.clone(),
        }))?;
        let justification = if next.document_layout_override.is_some() {
            LAYOUT_SET_JUSTIFICATION
        } else {
            LAYOUT_CLEAR_JUSTIFICATION
        };
        crate::try_append_event(
            &mut ledger,
            &actor,
            &layout_scope,
            "entity.document_layout_updated",
            Some(justification),
            &layout_payload,
        )?;
        appended += 1;
    }
    if statute_changed || fiscal_year_end_changed {
        ledger.append(
            &actor,
            &entity_scope,
            "entity.statute_updated",
            Some(STATUTE_UPDATE_JUSTIFICATION),
            &entity_payload,
        );
        appended += 1;
    }
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, appended, move |tx| {
            tx.upsert_entity(&next_for_store)
        })
        .await?;
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

    let registry_extracts = state.registry_extracts.read().await;
    let cae = state.cae.read().await;
    let today = time::OffsetDateTime::now_utc().date();
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
            registry_summary: registry_extracts
                .get(&e.id)
                .map(|extract| EntityRegistrySummaryView::build(extract, &cae, today)),
        })
        .collect();
    Ok(Json(out))
}

/// Bounded, searchable companion to [`list_entities`].
///
/// The legacy route intentionally remains a bare array. This opt-in route omits a total count so an
/// RBAC-filtered caller learns only about rows they can read; `offset` and `has_more` are computed
/// after authorization and search filtering.
#[derive(Debug, Deserialize)]
pub struct EntityPageQuery {
    q: Option<String>,
    #[serde(default)]
    offset: usize,
    cursor: Option<String>,
    limit: Option<usize>,
    sort: Option<String>,
    order: Option<String>,
    tenant_id: Option<Uuid>,
    group_id: Option<Uuid>,
    family: Option<EntityFamily>,
    kind: Option<EntityKind>,
    nipc_validated: Option<bool>,
    registry_import: Option<String>,
    registry_freshness: Option<String>,
    books: Option<String>,
    book_kind: Option<chancela_core::BookKind>,
    last_book: Option<String>,
    activity: Option<String>,
    activity_kind: Option<String>,
}

impl EntityPageQuery {
    fn page(&self) -> CollectionPageQuery {
        CollectionPageQuery {
            q: self.q.clone(),
            offset: self.offset,
            cursor: self.cursor.clone(),
            limit: self.limit,
            sort: self.sort.clone(),
            order: self.order.clone(),
        }
    }
}

fn entity_page_position(entity: &Entity, sort: &str) -> CursorPosition {
    let key = match sort {
        "nipc" => entity.nipc.to_string(),
        "id" => entity.id.to_string(),
        "family" => format!("{:?}", entity.family),
        "kind" => format!("{:?}", entity.kind),
        _ => entity.name.to_lowercase(),
    };
    CursorPosition::new(key, entity.id.to_string())
}

fn activity_category(kind: &str) -> &'static str {
    if kind == "registry.imported" {
        "registry"
    } else if kind.starts_with("entity.") {
        "entity"
    } else if kind.starts_with("book.") {
        "book"
    } else if kind.starts_with("act.") || kind.starts_with("convening.") {
        "act"
    } else if kind.starts_with("document.") || kind.starts_with("signature.") {
        "document"
    } else {
        "other"
    }
}

fn entity_family_search_labels(family: EntityFamily) -> &'static str {
    match family {
        EntityFamily::CommercialCompany => "Sociedade comercial Commercial Company",
        EntityFamily::Condominium => "Condomínio Condominio Condominium",
        EntityFamily::Association => "Associação Associacao Association",
        EntityFamily::Foundation => "Fundação Fundacao Foundation",
        EntityFamily::Cooperative => "Cooperativa Cooperative",
    }
}

fn entity_kind_search_labels(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::SociedadeEmNomeColetivo => "Sociedade em Nome Coletivo General Partnership",
        EntityKind::SociedadePorQuotas => "Sociedade por Quotas Private Limited Company",
        EntityKind::SociedadeUnipessoalPorQuotas => {
            "Sociedade Unipessoal por Quotas Single Member Private Limited Company"
        }
        EntityKind::SociedadeAnonima => {
            "Sociedade Anónima Sociedade Anonima Public Limited Company"
        }
        EntityKind::SociedadeEmComanditaSimples => {
            "Sociedade em Comandita Simples Limited Partnership"
        }
        EntityKind::SociedadeEmComanditaPorAcoes => {
            "Sociedade em Comandita por Ações Sociedade em Comandita por Acoes Partnership Limited by Shares"
        }
        EntityKind::Condominio => "Condomínio Condominio Condominium",
        EntityKind::Associacao => "Associação Associacao Association",
        EntityKind::Fundacao => "Fundação Fundacao Foundation",
        EntityKind::Cooperativa => "Cooperativa Cooperative",
    }
}

fn book_kind_search_labels(kind: BookKind) -> &'static str {
    match kind {
        BookKind::AssembleiaGeral => "Assembleia Geral General Meeting",
        BookKind::GerenciaAdministracao => {
            "Gerência Administração Gerencia Administracao Management Administration"
        }
        BookKind::ConselhoFiscal => "Conselho Fiscal Audit Board",
        BookKind::Condominio => "Condomínio Condominio Condominium",
        BookKind::Other => "Outro Other",
    }
}

fn book_state_search_labels(state: BookState) -> &'static str {
    match state {
        BookState::Created => "Criado Created",
        BookState::Open => "Aberto Open",
        BookState::Closed => "Encerrado Closed",
    }
}

fn closing_reason_search_labels(reason: &ClosingReason) -> &'static str {
    match reason {
        ClosingReason::BookFull => "Livro completo Book full",
        ClosingReason::EntityDissolved => "Entidade dissolvida Entity dissolved",
        ClosingReason::MigrationToSuccessor => {
            "Migração para livro sucessor Migracao para livro sucessor Migration to successor"
        }
        ClosingReason::Other { .. } => "Outro Other",
    }
}

fn spaced_identifier(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    let mut previous_was_lowercase = false;
    for character in value.chars() {
        if matches!(character, '.' | '_' | '-') {
            if !out.ends_with(' ') {
                out.push(' ');
            }
            previous_was_lowercase = false;
            continue;
        }
        if character.is_uppercase() && previous_was_lowercase {
            out.push(' ');
        }
        previous_was_lowercase = character.is_lowercase();
        out.push(character);
    }
    out
}

/// Practical primary-locale aliases for the activity labels surfaced in the entity registry.
/// Unknown/new kinds still receive a canonical spaced identifier, so paging never depends on the
/// web bundle's translation catalog and newer servers remain searchable by readable machine words.
fn activity_kind_search_labels(kind: &str) -> String {
    let localized = match kind {
        "registry.imported" => "Certidão do registo comercial importada Registo importado",
        "registry.auto_update.attempted" => "Atualização automática do registo comercial tentada",
        "entity.created" => "Entidade criada",
        "entity.statute_updated" => "Estatutos da entidade atualizados",
        "entity.document_layout_updated" => "Formato dos documentos da entidade atualizado",
        "book.opened" => "Livro aberto",
        "book.closed" => "Livro encerrado",
        "book.document_layout_updated" => "Formato dos documentos do livro atualizado",
        "book.legal_hold.set" => "Retenção legal do livro aplicada",
        "book.legal_hold.cleared" => "Retenção legal do livro levantada",
        "act.advanced" => "Ata avançada de estado",
        "act.archived" => "Ata arquivada",
        "act.drafted" => "Ata rascunhada",
        "act.reopened" => "Ata reaberta para correção",
        "act.reverted" => "Ata revertida para estado anterior",
        "act.sealed" => "Ata selada",
        "act.updated" => "Ata atualizada",
        "convening.dispatched" => "Convocatória expedida",
        "document.generated" => "Documento gerado",
        "document.imported" => "Documento importado",
        "document.signed" => "Documento assinado",
        _ => "",
    };
    format!("{localized} {}", spaced_identifier(kind))
}

fn entity_search_aliases(
    entity: &EntityView,
    books: &[BookView],
    activity: Option<&Event>,
    has_registry_extract: bool,
) -> String {
    let mut aliases = vec![
        entity_family_search_labels(entity.family).to_owned(),
        entity_kind_search_labels(entity.kind).to_owned(),
        if entity.nipc_validated {
            "NIPC validado".to_owned()
        } else {
            "NIPC por validar NIPC não validado".to_owned()
        },
        if has_registry_extract {
            "Registo importado".to_owned()
        } else {
            "Registo não importado".to_owned()
        },
    ];
    for book in books {
        aliases.push(book_kind_search_labels(book.kind).to_owned());
        aliases.push(book_state_search_labels(book.state).to_owned());
        if let Some(reason) = book.closing_reason.as_ref() {
            aliases.push(closing_reason_search_labels(reason).to_owned());
        }
    }
    if let Some(activity) = activity {
        aliases.push(activity_kind_search_labels(&activity.kind));
    }
    aliases.join(" ")
}

pub async fn list_entities_page(
    State(state): State<AppState>,
    Query(query): Query<EntityPageQuery>,
    actor: CurrentActor,
) -> Result<Json<CollectionPage<EntityListItemView>>, ApiError> {
    let authz = crate::authz::authorizer(&state, &actor).await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let page_query = query.page();
    let descending = page_query.descending()?;
    let sort = page_query.sort.as_deref().unwrap_or("name");
    if !matches!(sort, "name" | "nipc" | "family" | "kind" | "id") {
        return Err(ApiError::Unprocessable(format!(
            "unknown entity sort {sort:?}: expected \"name\", \"nipc\", \"family\", \"kind\" or \"id\""
        )));
    }
    let search = page_query.normalized_search();
    let limit = page_query.limit();
    if !matches!(
        query.registry_import.as_deref(),
        None | Some("imported" | "not-imported")
    ) {
        return Err(ApiError::Unprocessable(
            "unknown registry_import filter".to_owned(),
        ));
    }
    if !matches!(
        query.registry_freshness.as_deref(),
        None | Some("fresh" | "expired" | "no-expiry")
    ) {
        return Err(ApiError::Unprocessable(
            "unknown registry_freshness filter".to_owned(),
        ));
    }
    if !matches!(
        query.books.as_deref(),
        None | Some("open" | "created" | "closed" | "no-open" | "none")
    ) {
        return Err(ApiError::Unprocessable(
            "unknown entity books filter".to_owned(),
        ));
    }
    if !matches!(
        query.last_book.as_deref(),
        None | Some("Open" | "Created" | "Closed" | "none")
    ) {
        return Err(ApiError::Unprocessable(
            "unknown last_book filter".to_owned(),
        ));
    }
    if !matches!(
        query.activity.as_deref(),
        None | Some("registry" | "entity" | "book" | "act" | "document" | "none")
    ) {
        return Err(ApiError::Unprocessable(
            "unknown entity activity filter".to_owned(),
        ));
    }
    let fingerprint = query_fingerprint([
        ("q", search.clone().unwrap_or_default()),
        ("sort", sort.to_owned()),
        ("order", if descending { "desc" } else { "asc" }.to_owned()),
        (
            "tenant_id",
            query.tenant_id.map(|id| id.to_string()).unwrap_or_default(),
        ),
        (
            "group_id",
            query.group_id.map(|id| id.to_string()).unwrap_or_default(),
        ),
        (
            "family",
            query
                .family
                .map(|value| format!("{value:?}"))
                .unwrap_or_default(),
        ),
        (
            "kind",
            query
                .kind
                .map(|value| format!("{value:?}"))
                .unwrap_or_default(),
        ),
        (
            "nipc_validated",
            query
                .nipc_validated
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        (
            "registry_import",
            query.registry_import.clone().unwrap_or_default(),
        ),
        (
            "registry_freshness",
            query.registry_freshness.clone().unwrap_or_default(),
        ),
        ("books", query.books.clone().unwrap_or_default()),
        (
            "book_kind",
            query
                .book_kind
                .map(|value| format!("{value:?}"))
                .unwrap_or_default(),
        ),
        ("last_book", query.last_book.clone().unwrap_or_default()),
        ("activity", query.activity.clone().unwrap_or_default()),
        (
            "activity_kind",
            query.activity_kind.clone().unwrap_or_default(),
        ),
    ]);
    let cursor = page_query.cursor("entities", &fingerprint)?;

    let entities = state.entities.read().await;
    let mut visible: Vec<_> = entities
        .values()
        .filter(|entity| authz.permits(Permission::EntityRead, scope_of_entity(entity.id)))
        .filter(|entity| {
            query
                .tenant_id
                .is_none_or(|tenant_id| entity.tenant_id.0 == tenant_id)
        })
        .filter(|entity| {
            query
                .group_id
                .is_none_or(|group_id| entity.group_id.is_some_and(|id| id.0 == group_id))
        })
        .filter(|entity| query.family.is_none_or(|family| entity.family == family))
        .filter(|entity| query.kind.is_none_or(|kind| entity.kind == kind))
        .filter(|entity| {
            query
                .nipc_validated
                .is_none_or(|validated| entity.nipc.is_validated() == validated)
        })
        .collect();

    let visible_ids: HashSet<_> = visible.iter().map(|entity| entity.id).collect();
    let books = state.books.read().await;
    let readable_books: Vec<_> = books
        .values()
        .filter(|book| visible_ids.contains(&book.entity_id))
        .filter(|book| authz.permits(Permission::BookRead, scope_of_book(book.id)))
        .collect();
    let mut books_by_entity: HashMap<EntityId, Vec<&Book>> = HashMap::new();
    for book in &readable_books {
        books_by_entity
            .entry(book.entity_id)
            .or_default()
            .push(*book);
    }
    let registry_extracts = state.registry_extracts.read().await;
    let cae = state.cae.read().await;
    let today = time::OffsetDateTime::now_utc().date();
    let ledger = if authz.permits(Permission::LedgerRead, Scope::Global) {
        Some(state.ledger.read().await)
    } else {
        None
    };
    let events = ledger.as_ref().map(|ledger| ledger.events());
    let mut book_entity_ids = HashMap::new();
    for book in &readable_books {
        book_entity_ids.insert(book.id, book.entity_id);
    }
    let mut last_activity: HashMap<EntityId, &Event> = HashMap::new();
    if let Some(events) = events {
        for event in events.iter().rev() {
            for entity_id in collect_event_entity_ids(event, &visible_ids, &book_entity_ids) {
                last_activity.entry(entity_id).or_insert(event);
            }
            if last_activity.len() == visible_ids.len() {
                break;
            }
        }
    }
    visible.retain(|entity| {
        let entity_books = books_by_entity
            .get(&entity.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let last_book = entity_books
            .iter()
            .copied()
            .max_by(|left, right| compare_last_book(left, right));
        let extract = registry_extracts.get(&entity.id);
        let activity = last_activity.get(&entity.id).copied();
        let state_count = |state| {
            entity_books
                .iter()
                .filter(|book| book.state == state)
                .count()
        };
        let registry_matches = match query.registry_import.as_deref() {
            Some("imported") => extract.is_some(),
            Some("not-imported") => extract.is_none(),
            _ => true,
        };
        let freshness_matches = match query.registry_freshness.as_deref() {
            Some("fresh") => extract.is_some_and(|extract| {
                compute_expired(extract.provenance.valid_until.as_deref(), today) == Some(false)
            }),
            Some("expired") => extract.is_some_and(|extract| {
                compute_expired(extract.provenance.valid_until.as_deref(), today) == Some(true)
            }),
            Some("no-expiry") => extract.is_none_or(|extract| {
                compute_expired(extract.provenance.valid_until.as_deref(), today).is_none()
            }),
            _ => true,
        };
        let books_match = match query.books.as_deref() {
            Some("open") => state_count(BookState::Open) > 0,
            Some("created") => state_count(BookState::Created) > 0,
            Some("closed") => state_count(BookState::Closed) > 0,
            Some("no-open") => state_count(BookState::Open) == 0,
            Some("none") => entity_books.is_empty(),
            _ => true,
        };
        let kind_matches = query
            .book_kind
            .is_none_or(|kind| entity_books.iter().any(|book| book.kind == kind));
        let last_book_matches = match query.last_book.as_deref() {
            Some("Open") => last_book.is_some_and(|book| book.state == BookState::Open),
            Some("Created") => last_book.is_some_and(|book| book.state == BookState::Created),
            Some("Closed") => last_book.is_some_and(|book| book.state == BookState::Closed),
            Some("none") => last_book.is_none(),
            _ => true,
        };
        let activity_matches = match query.activity.as_deref() {
            Some("none") => activity.is_none(),
            Some(category) => {
                activity.is_some_and(|event| activity_category(&event.kind) == category)
            }
            None => true,
        };
        let activity_kind_matches = match query.activity_kind.as_deref() {
            Some("none") => activity.is_none(),
            Some(kind) => activity.is_some_and(|event| event.kind == kind),
            None => true,
        };
        let search_matches = search.as_ref().is_none_or(|needle| {
            let entity_view = EntityView::build(entity, redaction);
            let book_views: Vec<_> = entity_books
                .iter()
                .map(|book| BookView::build(book, redaction))
                .collect();
            let registry_view =
                extract.map(|extract| EntityRegistrySummaryView::build(extract, &cae, today));
            let activity_view = activity.map(LedgerEventView::from);
            let aliases =
                entity_search_aliases(&entity_view, &book_views, activity, extract.is_some());
            serde_json::to_string(&(entity_view, book_views, registry_view, activity_view))
                .is_ok_and(|text| fold_search(&format!("{text} {aliases}")).contains(needle))
        });
        registry_matches
            && freshness_matches
            && books_match
            && kind_matches
            && last_book_matches
            && activity_matches
            && activity_kind_matches
            && search_matches
    });
    visible.sort_by(|left, right| {
        let ordering = match sort {
            "nipc" => left
                .nipc
                .to_string()
                .cmp(&right.nipc.to_string())
                .then(left.id.0.cmp(&right.id.0)),
            "id" => left.id.0.cmp(&right.id.0),
            "family" => format!("{:?}", left.family)
                .cmp(&format!("{:?}", right.family))
                .then(left.id.0.cmp(&right.id.0)),
            "kind" => format!("{:?}", left.kind)
                .cmp(&format!("{:?}", right.kind))
                .then(left.id.0.cmp(&right.id.0)),
            _ => left
                .name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then(left.id.0.cmp(&right.id.0)),
        };
        if descending {
            ordering.reverse()
        } else {
            ordering
        }
    });

    apply_keyset(&mut visible, cursor.as_ref(), descending, |entity| {
        entity_page_position(entity, sort)
    });
    let page = CollectionPage::from_keyset_sorted(
        visible,
        page_query.offset,
        limit,
        cursor.is_some(),
        "entities",
        &fingerprint,
        |entity| entity_page_position(entity, sort),
    );
    let page_ids: HashSet<_> = page.items.iter().map(|entity| entity.id).collect();
    let mut summaries = entity_activity_summaries(
        &page_ids,
        readable_books
            .iter()
            .copied()
            .filter(|book| page_ids.contains(&book.entity_id)),
        events,
    );

    Ok(Json(page.map(|entity| {
        EntityListItemView {
            entity: EntityView::build(entity, redaction),
            activity_summary: summaries
                .remove(&entity.id)
                .unwrap_or_else(empty_activity_summary),
            registry_summary: registry_extracts
                .get(&entity.id)
                .map(|extract| EntityRegistrySummaryView::build(extract, &cae, today)),
        }
    })))
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
        // The ledger is append ordered. Walk newest-first and stop as soon as every requested
        // entity has a last-change event; a bounded page with recent activity normally examines only
        // a small tail instead of rescanning the complete historical chain.
        let mut unresolved = summaries.len();
        for event in events.iter().rev() {
            for entity_id in collect_event_entity_ids(event, entity_ids, &book_entity_ids) {
                let Some(summary) = summaries.get_mut(&entity_id) else {
                    continue;
                };
                if summary.last_change.is_none() {
                    summary.last_change = Some(event);
                    unresolved = unresolved.saturating_sub(1);
                }
            }
            if unresolved == 0 {
                break;
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
            // A tenant chain spans many entities and names none directly — it contributes no single
            // entity id to this per-entity index (wp26).
            ChainId::Tenant(_) | ChainId::Global | ChainId::Application => {}
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
        GUEST_ROLE_ID, OWNER_ROLE_ID, READER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId, Scope,
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
            serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                panic!(
                    "body is JSON ({error}); raw={:?}",
                    String::from_utf8_lossy(&bytes)
                )
            })
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

    fn patch_layout_json(uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method("PATCH")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    struct LayoutTempDir {
        path: std::path::PathBuf,
    }

    impl LayoutTempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("chancela-layout-api-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("temporary data directory created");
            Self { path }
        }
    }

    impl Drop for LayoutTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
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
            role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
            language: Default::default(),
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

    /// **Anti-leak guard (wp26 P3, plan §4.1.3).** The tenant isolation guarantee for the read path
    /// rests on the enumeration endpoints filtering **per row** through the resolved `Authorizer`
    /// (`authz.permits(perm, scope_of_{entity,book}(id))`), because `scope_covers` enforces
    /// tenant→entity→book containment on exactly that call. If a future edit replaced the per-row
    /// filter with a single up-front `require_permission` and an unfiltered `.values()` dump, a
    /// tenant-scoped user would see every tenant's rows. This test freezes the per-row filter into
    /// the two enumeration handlers so that regression fails the build. It does NOT prove every one
    /// of the ~101 read sites over entities/books/acts is tenant-safe (see the track's honest P3
    /// coverage note) — it guards the two proven, tenant-reachable enumeration choke points.
    #[test]
    fn enumeration_endpoints_retain_the_per_row_tenant_filter() {
        const ENTITIES_SRC: &str = include_str!("entities.rs");
        const BOOKS_SRC: &str = include_str!("books.rs");

        // list_entities filters entities per row on entity.read@Entity(id) and books on
        // book.read@Book(id) — both narrow through the tenant relation.
        let entities_list = ENTITIES_SRC
            .split_once("pub async fn list_entities")
            .expect("list_entities exists")
            .1;
        let entities_list = &entities_list[..entities_list
            .find("\npub async fn ")
            .unwrap_or(entities_list.len())];
        assert!(
            entities_list.contains("authz.permits(Permission::EntityRead, scope_of_entity("),
            "list_entities lost its per-row entity.read tenant filter — cross-tenant leak risk"
        );
        assert!(
            entities_list.contains("authz.permits(Permission::BookRead, scope_of_book("),
            "list_entities lost its per-row book.read tenant filter — cross-tenant leak risk"
        );

        // list_books filters books per row on book.read@Book(id).
        let books_list = BOOKS_SRC
            .split_once("pub async fn list_books")
            .expect("list_books exists")
            .1;
        let books_list = &books_list[..books_list
            .find("\npub async fn ")
            .unwrap_or(books_list.len())];
        assert!(
            books_list.contains("authz.permits(Permission::BookRead, scope_of_book("),
            "list_books lost its per-row book.read tenant filter — cross-tenant leak risk"
        );

        let entities_page = ENTITIES_SRC
            .split_once("pub async fn list_entities_page")
            .expect("list_entities_page exists")
            .1;
        let entities_page = &entities_page[..entities_page
            .find("\npub async fn ")
            .unwrap_or(entities_page.len())];
        assert!(
            entities_page.contains("authz.permits(Permission::EntityRead, scope_of_entity("),
            "list_entities_page lost its per-row entity.read tenant filter"
        );
        assert!(
            entities_page.contains("authz.permits(Permission::BookRead, scope_of_book("),
            "list_entities_page lost its per-row book.read tenant filter"
        );

        let books_page = BOOKS_SRC
            .split_once("pub async fn list_books_page")
            .expect("list_books_page exists")
            .1;
        let books_page = &books_page[..books_page
            .find("\npub async fn ")
            .unwrap_or(books_page.len())];
        assert!(
            books_page.contains("authz.permits(Permission::BookRead, scope_of_book("),
            "list_books_page lost its per-row book.read tenant filter"
        );
    }

    /// Like [`token_for_role`] but assigns the role at an arbitrary `scope` (wp26: a
    /// `Scope::Tenant(..)` assignment), so the two-tenant fixture can mint a user rooted at exactly
    /// one tenant.
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

        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: username.to_owned(),
            display_name: username.to_owned(),
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
            role_assignments: vec![RoleAssignment::new(role_id, scope)],
            language: Default::default(),
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

    /// **Two-tenant isolation fixture (wp26 P2, plan §4.1.2).** Two tenants A and B each own an
    /// entity; a user is rooted at tenant A only (Owner role assigned at `Scope::Tenant(A)`). The
    /// user must see **only** A's entity in the list and get a non-enumerating `403` for B's entity,
    /// while a Global owner (control) sees both. This proves the `Scope::Tenant` narrowing level and
    /// the entity→tenant relation gate the existing per-row list filter (`entities.rs:202`).
    #[tokio::test]
    async fn tenant_isolation_entity_list_and_read_is_scoped_to_the_users_tenant() {
        use chancela_core::{Entity, EntityId, EntityKind, Nipc, TenantId};

        let state = AppState::default();

        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();

        // Insert one entity per tenant directly into state (the create endpoint stamps the default
        // tenant; here we need a genuinely multi-tenant fixture).
        let entity_a = Entity::new(
            "Encosto Estratégico A, Lda",
            Nipc::unvalidated("A-0001"),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(tenant_a);
        let entity_b = Entity::new(
            "Encosto Estratégico B, Lda",
            Nipc::unvalidated("B-0001"),
            "Porto",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(tenant_b);
        let id_a: EntityId = entity_a.id;
        let id_b: EntityId = entity_b.id;
        {
            let mut entities = state.entities.write().await;
            entities.insert(id_a, entity_a);
            entities.insert(id_b, entity_b);
        }

        // A user rooted at tenant A only (Owner grants entity.read; the scope narrows it to A).
        let scope_a = crate::authz::scope_of_tenant(tenant_a);
        let user_a = token_for_role_at(&state, "amelia.marques", OWNER_ROLE_ID, scope_a).await;

        // (1) The list shows exactly A's entity, never B's.
        let (status, list) =
            send_raw(state.clone(), with_session(get("/v1/entities"), &user_a)).await;
        assert_eq!(status, StatusCode::OK);
        let ids: Vec<&str> = list
            .as_array()
            .expect("list is an array")
            .iter()
            .map(|row| row["id"].as_str().expect("row id"))
            .collect();
        assert_eq!(
            ids,
            vec![id_a.to_string().as_str()],
            "tenant-A user must see only tenant-A's entity, got {ids:?}"
        );
        let body = list.to_string();
        assert!(
            !body.contains(&id_b.to_string()),
            "tenant B's entity id leaked into A's list: {body}"
        );

        // (2) Reading A's own entity succeeds.
        let (status, _) = send_raw(
            state.clone(),
            with_session(get(&format!("/v1/entities/{id_a}")), &user_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // (3) Reading B's entity is a non-enumerating 403 (never 200, never a distinguishable 404).
        let (status, _) = send_raw(
            state.clone(),
            with_session(get(&format!("/v1/entities/{id_b}")), &user_a),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "tenant-A user must be forbidden from reading tenant-B's entity"
        );

        // (4) The book-enumeration path inherits the same tenant gate (books.rs:196 filters per row
        // through the Authorizer via scope_of_book → entity → tenant). Give each tenant a book and
        // assert the tenant-A user sees only A's book on GET /v1/books.
        use chancela_core::{Book, BookId, BookKind};
        let book_a = Book::new(id_a, BookKind::AssembleiaGeral);
        let book_b = Book::new(id_b, BookKind::AssembleiaGeral);
        let bid_a: BookId = book_a.id;
        let bid_b: BookId = book_b.id;
        {
            let mut books = state.books.write().await;
            books.insert(bid_a, book_a);
            books.insert(bid_b, book_b);
        }
        let (status, blist) =
            send_raw(state.clone(), with_session(get("/v1/books"), &user_a)).await;
        assert_eq!(status, StatusCode::OK);
        let book_ids: Vec<&str> = blist
            .as_array()
            .expect("books is an array")
            .iter()
            .map(|row| row["id"].as_str().expect("book id"))
            .collect();
        assert_eq!(
            book_ids,
            vec![bid_a.to_string().as_str()],
            "tenant-A user must see only tenant-A's book, got {book_ids:?}"
        );

        // (5) Control: a Global owner sees BOTH entities and BOTH books — the fixture is genuinely
        // populated and the isolation above is the tenant boundary, not an empty state.
        let global_owner =
            token_for_role_at(&state, "global.owner", OWNER_ROLE_ID, Scope::Global).await;
        let (status, list) = send_raw(
            state.clone(),
            with_session(get("/v1/entities"), &global_owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            list.as_array().expect("array").len(),
            2,
            "a Global owner must see both tenants' entities"
        );
        let (status, blist) =
            send_raw(state.clone(), with_session(get("/v1/books"), &global_owner)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            blist.as_array().expect("array").len(),
            2,
            "a Global owner must see both tenants' books"
        );
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

        let leitor = token_for_role(&state, "leitor", READER_ROLE_ID).await;
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
                required_signatory_records: Vec::new(),
                ..Default::default()
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
                required_signatory_records: Vec::new(),
                ..Default::default()
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
                required_signatory_records: Vec::new(),
                ..Default::default()
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

    #[tokio::test]
    async fn entity_page_is_bounded_and_filters_before_offsetting() {
        let state = AppState::default();
        let token = token_for_role(&state, "owner.page", OWNER_ROLE_ID).await;
        let alpha = Entity::new(
            "Alpha Holdings",
            Nipc::unvalidated("alpha-nipc"),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        );
        let beta = Entity::new(
            "Beta Holdings",
            Nipc::unvalidated("beta-nipc"),
            "Porto",
            EntityKind::SociedadePorQuotas,
        );
        let unrelated = Entity::new(
            "Unrelated",
            Nipc::unvalidated("other-nipc"),
            "Braga",
            EntityKind::SociedadePorQuotas,
        );
        state
            .entities
            .write()
            .await
            .extend([alpha, beta, unrelated].map(|entity| (entity.id, entity)));

        let (status, body) = send_raw(
            state,
            with_session(
                get("/v1/entities/page?q=holdings&sort=name&limit=1&offset=1"),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["name"], "Beta Holdings");
        assert_eq!(body["offset"], 1);
        assert_eq!(body["limit"], 1);
        assert_eq!(body["has_more"], false);
        assert!(body.get("total").is_none(), "RBAC page exposes no total");
    }

    #[tokio::test]
    async fn entity_page_search_preserves_primary_portuguese_labels() {
        let state = AppState::default();
        let token = token_for_role(&state, "owner.search-labels", OWNER_ROLE_ID).await;
        let alpha = Entity::new(
            "Alpha Participações",
            Nipc::unvalidated("alpha-labels"),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        );
        let beta = Entity::new(
            "Beta Participações",
            Nipc::unvalidated("beta-labels"),
            "Porto",
            EntityKind::SociedadePorQuotas,
        );
        let alpha_id = alpha.id;
        let beta_id = beta.id;
        state
            .entities
            .write()
            .await
            .extend([alpha, beta].map(|entity| (entity.id, entity)));

        let mut closed_book = Book::new(alpha_id, BookKind::AssembleiaGeral);
        closed_book.state = BookState::Closed;
        closed_book.termo_encerramento = Some(TermoDeEncerramento::default());
        state
            .books
            .write()
            .await
            .insert(closed_book.id, closed_book);
        state.ledger.write().await.append(
            "owner.search-labels",
            &format!("entity:{beta_id}"),
            "entity.created",
            None,
            b"{}",
        );

        for (term, expected_ids) in [
            (
                "sociedade%20por%20quotas",
                vec![alpha_id.to_string(), beta_id.to_string()],
            ),
            (
                "sociedade%20comercial",
                vec![alpha_id.to_string(), beta_id.to_string()],
            ),
            ("assembleia%20geral", vec![alpha_id.to_string()]),
            ("encerrado", vec![alpha_id.to_string()]),
            ("livro%20completo", vec![alpha_id.to_string()]),
            ("entidade%20criada", vec![beta_id.to_string()]),
        ] {
            let (status, body) = send_raw(
                state.clone(),
                with_session(
                    get(&format!("/v1/entities/page?q={term}&sort=name&limit=10")),
                    &token,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "query {term}");
            let found: Vec<_> = body["items"]
                .as_array()
                .expect("page items")
                .iter()
                .map(|item| item["id"].as_str().expect("entity id").to_owned())
                .collect();
            for expected in expected_ids {
                assert!(
                    found.contains(&expected),
                    "query {term} did not include expected entity {expected}; found {found:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn document_layout_override_set_omit_clear_and_restart_are_durable_and_audited() {
        let temp = LayoutTempDir::new();
        let (entity_id, book_id) = {
            let state = AppState::with_data_dir(temp.path.clone());
            let owner = token_for_role(&state, "layout.owner", OWNER_ROLE_ID).await;

            let (status, entity) = send_raw(
                state.clone(),
                with_session(
                    post_json(
                        "/v1/entities",
                        json!({
                            "name": "Layout Persistente, Lda",
                            "nipc": "503004642",
                            "seat": "Lisboa",
                            "kind": "SociedadePorQuotas"
                        }),
                    ),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{entity}");
            assert!(entity["document_layout_override"].is_null());
            let entity_id = entity["id"].as_str().expect("entity id").to_owned();

            let (status, inherited) = send_raw(
                state.clone(),
                with_session(
                    patch_layout_json(
                        &format!("/v1/entities/{entity_id}"),
                        json!({ "document_layout_override": {} }),
                    ),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{inherited}");
            assert!(
                inherited["document_layout_override"].is_null(),
                "an override with no explicit leaves is canonical inheritance"
            );

            let (status, set) = send_raw(
                state.clone(),
                with_session(
                    patch_layout_json(
                        &format!("/v1/entities/{entity_id}"),
                        json!({
                            "document_layout_override": {
                                "page": { "orientation": "Landscape" },
                                "typography": { "heading_scale_percent": 115 }
                            }
                        }),
                    ),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{set}");
            assert_eq!(
                set["document_layout_override"]["page"]["orientation"],
                "Landscape"
            );

            let ledger_len = state.ledger.read().await.len();
            let (status, omitted) = send_raw(
                state.clone(),
                with_session(
                    patch_layout_json(&format!("/v1/entities/{entity_id}"), json!({})),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{omitted}");
            assert_eq!(
                omitted["document_layout_override"],
                set["document_layout_override"]
            );
            assert_eq!(state.ledger.read().await.len(), ledger_len);

            let (status, cleared) = send_raw(
                state.clone(),
                with_session(
                    patch_layout_json(
                        &format!("/v1/entities/{entity_id}"),
                        json!({ "document_layout_override": null }),
                    ),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{cleared}");
            assert!(cleared["document_layout_override"].is_null());

            let (status, entity_final) = send_raw(
                state.clone(),
                with_session(
                    patch_layout_json(
                        &format!("/v1/entities/{entity_id}"),
                        json!({
                            "document_layout_override": {
                                "page": { "margins_mm": { "top": 21 } }
                            }
                        }),
                    ),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{entity_final}");

            let (status, book) = send_raw(
                state.clone(),
                with_session(
                    post_json(
                        "/v1/books",
                        json!({
                            "entity_id": entity_id,
                            "kind": "AssembleiaGeral",
                            "purpose": "Livro de atas",
                            "opening_date": "",
                            "required_signatories": [],
                            "one_shot": false,
                            "document_layout_override": {
                                "typography": { "body_font_size_pt": 12 }
                            }
                        }),
                    ),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{book}");
            assert_eq!(
                book["document_layout_override"]["typography"]["body_font_size_pt"],
                12
            );
            let book_id = book["id"].as_str().expect("book id").to_owned();

            let ledger_len = state.ledger.read().await.len();
            let (status, omitted) = send_raw(
                state.clone(),
                with_session(
                    patch_layout_json(&format!("/v1/books/{book_id}"), json!({})),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{omitted}");
            assert_eq!(
                omitted["document_layout_override"],
                book["document_layout_override"]
            );
            assert_eq!(state.ledger.read().await.len(), ledger_len);

            let (status, cleared) = send_raw(
                state.clone(),
                with_session(
                    patch_layout_json(
                        &format!("/v1/books/{book_id}"),
                        json!({ "document_layout_override": null }),
                    ),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{cleared}");
            assert!(cleared["document_layout_override"].is_null());

            let (status, book_final) = send_raw(
                state.clone(),
                with_session(
                    patch_layout_json(
                        &format!("/v1/books/{book_id}"),
                        json!({
                            "document_layout_override": {
                                "regions": { "header_gap_mm": 7 }
                            }
                        }),
                    ),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{book_final}");
            assert_eq!(
                book_final["document_layout_override"]["regions"]["header_gap_mm"],
                7
            );

            let ledger = state.ledger.read().await;
            assert!(ledger.events().iter().any(|event| {
                event.kind == "entity.document_layout_updated"
                    && event.justification.as_deref()
                        == Some("entity document layout override cleared")
            }));
            assert!(ledger.events().iter().any(|event| {
                event.kind == "book.document_layout_updated"
                    && event.justification.as_deref() == Some("book document layout override set")
            }));
            assert!(ledger.events().iter().any(|event| {
                event.kind == "book.document_layout_updated"
                    && event.justification.as_deref()
                        == Some("book document layout override cleared")
            }));
            let book_layout_events: Vec<_> = ledger
                .events()
                .iter()
                .filter(|event| event.kind == "book.document_layout_updated")
                .collect();
            assert!(
                book_layout_events.iter().all(|event| event
                    .links
                    .iter()
                    .all(|link| !matches!(&link.chain, ChainId::Book(_)))),
                "a Created book must not join its book chain before book.opened"
            );
            assert!(
                ledger.verify().is_ok(),
                "layout edits must preserve all ledger genesis/link invariants"
            );

            (entity_id, book_id)
        };

        let restarted = AppState::with_data_dir(temp.path.clone());
        let entity_id = EntityId(Uuid::parse_str(&entity_id).expect("entity UUID"));
        let book_id = BookId(Uuid::parse_str(&book_id).expect("book UUID"));
        let entities = restarted.entities.read().await;
        assert_eq!(
            entities[&entity_id]
                .document_layout_override
                .as_ref()
                .and_then(|layout| layout.page.margins_mm.top),
            Some(21)
        );
        drop(entities);
        let books = restarted.books.read().await;
        assert_eq!(
            books[&book_id]
                .document_layout_override
                .as_ref()
                .and_then(|layout| layout.regions.header_gap_mm),
            Some(7)
        );
    }

    #[tokio::test]
    async fn document_layout_override_validation_is_atomic_across_inherited_layers() {
        let state = AppState::default();
        let owner = token_for_role(&state, "layout.validator", OWNER_ROLE_ID).await;
        let entity = Entity::new(
            "Layout Validation, Lda",
            Nipc::unvalidated("layout-validation"),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        );
        let entity_id = entity.id;
        let book = Book::new(entity_id, BookKind::AssembleiaGeral);
        let book_id = book.id;
        state.entities.write().await.insert(entity_id, entity);
        state.books.write().await.insert(book_id, book);
        state
            .ledger
            .write()
            .await
            .try_append(
                "layout.fixture",
                &format!("tenant:{DEFAULT_TENANT_ID}/entity:{entity_id}"),
                "entity.created",
                None,
                b"{}",
            )
            .expect("fixture entity genesis");

        let before_events = state.ledger.read().await.len();
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                patch_layout_json(
                    &format!("/v1/entities/{entity_id}"),
                    json!({
                        "document_layout_override": {
                            "page": { "margins_mm": { "top": 1 } }
                        }
                    }),
                ),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            state.entities.read().await[&entity_id]
                .document_layout_override
                .is_none()
        );
        assert_eq!(state.ledger.read().await.len(), before_events);

        let (status, entity_view) = send_raw(
            state.clone(),
            with_session(
                patch_layout_json(
                    &format!("/v1/entities/{entity_id}"),
                    json!({
                        "document_layout_override": {
                            "page": { "size": "A5" }
                        }
                    }),
                ),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{entity_view}");

        let before_events = state.ledger.read().await.len();
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                patch_layout_json(
                    &format!("/v1/books/{book_id}"),
                    json!({
                        "document_layout_override": {
                            "page": {
                                "margins_mm": { "left": 30, "right": 30 }
                            }
                        }
                    }),
                ),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            state.books.read().await[&book_id]
                .document_layout_override
                .is_none()
        );
        assert_eq!(state.ledger.read().await.len(), before_events);
    }

    #[tokio::test]
    async fn document_layout_override_patch_is_tenant_scoped_and_non_enumerating() {
        let state = AppState::default();
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let entity_a = Entity::new(
            "Tenant A Layout",
            Nipc::unvalidated("tenant-a-layout"),
            "Lisboa",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(tenant_a);
        let entity_b = Entity::new(
            "Tenant B Layout",
            Nipc::unvalidated("tenant-b-layout"),
            "Porto",
            EntityKind::SociedadePorQuotas,
        )
        .in_tenant(tenant_b);
        let entity_a_id = entity_a.id;
        let entity_b_id = entity_b.id;
        let book_a = Book::new(entity_a_id, BookKind::AssembleiaGeral);
        let book_b = Book::new(entity_b_id, BookKind::AssembleiaGeral);
        let book_a_id = book_a.id;
        let book_b_id = book_b.id;
        state
            .entities
            .write()
            .await
            .extend([(entity_a_id, entity_a), (entity_b_id, entity_b)]);
        state
            .books
            .write()
            .await
            .extend([(book_a_id, book_a), (book_b_id, book_b)]);
        {
            let mut ledger = state.ledger.write().await;
            for (tenant_id, entity_id) in [(tenant_a, entity_a_id), (tenant_b, entity_b_id)] {
                ledger
                    .try_append(
                        "layout.fixture",
                        &format!("tenant:{tenant_id}/entity:{entity_id}"),
                        "entity.created",
                        None,
                        b"{}",
                    )
                    .expect("fixture entity genesis");
            }
        }

        let tenant_owner = token_for_role_at(
            &state,
            "layout.tenant-owner",
            OWNER_ROLE_ID,
            scope_of_tenant(tenant_a),
        )
        .await;
        let global_owner = token_for_role(&state, "layout.global-owner", OWNER_ROLE_ID).await;
        let reader = token_for_role(&state, "layout.reader", READER_ROLE_ID).await;
        let body = json!({
            "document_layout_override": {
                "typography": { "paragraph_spacing_pt": 8 }
            }
        });

        for uri in [
            format!("/v1/entities/{entity_a_id}"),
            format!("/v1/books/{book_a_id}"),
        ] {
            let (status, response) = send_raw(
                state.clone(),
                with_session(patch_layout_json(&uri, body.clone()), &tenant_owner),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{uri}: {response}");
        }

        for uri in [
            format!("/v1/entities/{entity_b_id}"),
            format!("/v1/books/{book_b_id}"),
        ] {
            let (status, _) = send_raw(
                state.clone(),
                with_session(patch_layout_json(&uri, body.clone()), &tenant_owner),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        }

        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_layout_json(&format!("/v1/books/{book_a_id}"), body.clone()),
                &reader,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        for uri in [
            format!("/v1/entities/{}", Uuid::new_v4()),
            format!("/v1/books/{}", Uuid::new_v4()),
        ] {
            let (status, _) = send_raw(
                state.clone(),
                with_session(patch_layout_json(&uri, body.clone()), &global_owner),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }

        let ledger = state.ledger.read().await;
        let tenant_a_layout_events: Vec<_> = ledger
            .events()
            .iter()
            .filter(|event| event.kind.ends_with(".document_layout_updated"))
            .collect();
        assert_eq!(tenant_a_layout_events.len(), 2);
        assert!(tenant_a_layout_events.iter().all(|event| {
            event.scope == format!("tenant:{tenant_a}/entity:{entity_a_id}")
                && event.links.iter().any(
                    |link| matches!(&link.chain, ChainId::Tenant(id) if id == &tenant_a.to_string()),
                )
        }));
        assert!(ledger.verify().is_ok());
    }
}
