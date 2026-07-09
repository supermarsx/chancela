//! Dashboard endpoint (contract §2.7): the WFL-40 counts plus the recent-events feed.

use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use chancela_core::{
    Act, ActId, ActState, Book, BookId, BookKind, BookState, CalendarPreset, Entity, EntityFamily,
    EntityId, EntityKind, EntityProfile, Severity, profile_for, rule_pack_for,
};
use chancela_law::LawCatalog;
use chancela_registry::RegistryExtract;
use time::{Date, Month, OffsetDateTime};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::dto::{
    DashboardActStateCounts, DashboardAction, DashboardAlert, DashboardAlertTarget,
    DashboardCurrentWork, DashboardI18n, DashboardLawReference, DashboardOpenBook,
    DashboardReminder, DashboardResponse, DashboardTargetLinks, LedgerEventView, compute_expired,
    format_date,
};
use crate::error::ApiError;

const DASHBOARD_REMINDER_LIMIT: usize = 5;
const REGISTRY_EXPIRY_WARNING_DAYS: i32 = 30;

/// `GET /v1/dashboard` — aggregate counts and the last ten ledger events.
pub async fn dashboard(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<DashboardResponse>, ApiError> {
    // RBAC (t64-E3): the dashboard aggregates act data → `act.read` at Global.
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;
    // entities → books → acts → registry_extracts → ledger (read locks; the global order).
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;
    let registry_extracts = state.registry_extracts.read().await;
    let ledger = state.ledger.read().await;

    let books_open = books
        .values()
        .filter(|b| b.state == BookState::Open)
        .count();

    let mut acts_draft = 0usize;
    let mut acts_awaiting_signature = 0usize;
    let mut acts_sealed = 0usize;
    let mut unresolved_compliance = 0usize;
    for act in acts.values() {
        match act.state {
            ActState::Draft
            | ActState::Review
            | ActState::Convened
            | ActState::Deliberated
            | ActState::TextApproved => acts_draft += 1,
            ActState::Signing => {
                acts_awaiting_signature += 1;
                // A Signing act still carrying compliance errors is "unresolved".
                if let Some(book) = books.get(&act.book_id) {
                    if let Some(entity) = entities.get(&book.entity_id) {
                        // Per-family dispatch (R4): check against the entity's own pack.
                        let has_error = rule_pack_for(entity)
                            .check_act(act, entity)
                            .iter()
                            .any(|i| i.severity == Severity::Error);
                        if has_error {
                            unresolved_compliance += 1;
                        }
                    }
                }
            }
            ActState::Sealed | ActState::Archived => acts_sealed += 1,
        }
    }

    let (ledger_valid, ledger_length) = match ledger.verify() {
        Ok(len) => (true, len),
        Err(_) => (false, ledger.len() as u64),
    };

    // Last ten events in append order.
    let events = ledger.events();
    let start = events.len().saturating_sub(10);
    let recent_events = events[start..].iter().map(LedgerEventView::from).collect();
    let today = OffsetDateTime::now_utc().date();
    let current_work = dashboard_current_work(&entities, &books, &acts);
    let alerts = dashboard_alerts(
        &entities,
        &books,
        &acts,
        &registry_extracts,
        ledger_valid,
        today,
    );
    let reminders = dashboard_reminders(&entities, &books, &acts, &registry_extracts, today);

    Ok(Json(DashboardResponse {
        entities: entities.len(),
        books_open,
        books_total: books.len(),
        acts_total: acts.len(),
        acts_draft,
        acts_awaiting_signature,
        acts_sealed,
        unresolved_compliance,
        ledger_length,
        ledger_valid,
        current_work,
        alerts,
        reminders,
        recent_events,
    }))
}

fn dashboard_current_work(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
) -> DashboardCurrentWork {
    DashboardCurrentWork {
        open_books: dashboard_open_books(entities, books, acts),
        act_counts_by_state: dashboard_act_counts_by_state(acts),
    }
}

fn dashboard_act_counts_by_state(acts: &HashMap<ActId, Act>) -> DashboardActStateCounts {
    let mut counts = DashboardActStateCounts::default();
    for act in acts.values() {
        match act.state {
            ActState::Draft => counts.draft += 1,
            ActState::Review => counts.review += 1,
            ActState::Convened => counts.convened += 1,
            ActState::Deliberated => counts.deliberated += 1,
            ActState::TextApproved => counts.text_approved += 1,
            ActState::Signing => counts.signing += 1,
            ActState::Sealed => counts.sealed += 1,
            ActState::Archived => counts.archived += 1,
        }
    }
    counts
}

fn dashboard_open_books(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
) -> Vec<DashboardOpenBook> {
    let mut rows = books
        .values()
        .filter(|book| book.state == BookState::Open)
        .map(|book| {
            let entity = entities.get(&book.entity_id);
            let book_acts = acts
                .values()
                .filter(|act| act.book_id == book.id)
                .collect::<Vec<_>>();
            let total_acts = book_acts.len();
            let open_acts = book_acts.iter().filter(|act| act.is_mutable()).count();
            DashboardOpenBook {
                book_id: book.id.to_string(),
                entity_id: book.entity_id.to_string(),
                entity_name: entity.map(|entity| entity.name.clone()),
                kind: book.kind,
                purpose: book
                    .termo_abertura
                    .as_ref()
                    .map(|termo| termo.purpose.clone()),
                opening_date: book
                    .termo_abertura
                    .as_ref()
                    .map(|termo| format_date(termo.opening_date)),
                last_ata_number: book.last_ata_number,
                total_acts,
                open_acts,
                next_ata_number: book.last_ata_number.saturating_add(1),
                links: target_links(Some(book.entity_id), Some(book.id), None),
            }
        })
        .collect::<Vec<_>>();

    rows.sort_by(|a, b| {
        a.entity_name
            .cmp(&b.entity_name)
            .then_with(|| a.entity_id.cmp(&b.entity_id))
            .then_with(|| a.opening_date.cmp(&b.opening_date))
            .then_with(|| a.book_id.cmp(&b.book_id))
    });
    rows
}

fn dashboard_alerts(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    registry_extracts: &HashMap<EntityId, RegistryExtract>,
    ledger_valid: bool,
    today: Date,
) -> Vec<DashboardAlert> {
    let mut alerts = Vec::new();

    if !ledger_valid {
        alerts.push(DashboardAlert {
            code: "ledger.integrity.review_required".to_owned(),
            label: "ReviewRequired".to_owned(),
            severity: "Error".to_owned(),
            category: "LedgerIntegrity".to_owned(),
            message: "The dashboard could not verify the ledger chain. Review the ledger integrity report before relying on the audit trail.".to_owned(),
            params: dashboard_alert_params([]),
            target: DashboardAlertTarget {
                entity_id: None,
                book_id: None,
                act_id: None,
                links: DashboardTargetLinks {
                    entity: None,
                    book: None,
                    act: None,
                    ledger: Some("/v1/ledger/integrity".to_owned()),
                },
            },
            source: Some("ledger.verify".to_owned()),
            law_refs: Vec::new(),
            action: Some(dashboard_action(
                "open_ledger",
                "notifications.alert.ledger.integrity.action",
                Some("/v1/ledger/integrity".to_owned()),
                Some("/arquivo".to_owned()),
            )),
            recommended_next_steps: vec![
                "Open the ledger integrity report.".to_owned(),
                "Resolve or re-anchor chain breaks before relying on archive evidence.".to_owned(),
            ],
            i18n: Some(alert_i18n(
                "notifications.alert.ledger.integrity.title",
                "notifications.alert.ledger.integrity.body",
                Some("notifications.alert.ledger.integrity.action"),
            )),
        });
    }

    push_lifecycle_alerts(&mut alerts, entities, books, acts, registry_extracts);

    for act in acts.values() {
        if act.state != ActState::Signing {
            continue;
        }
        let Some(book) = books.get(&act.book_id) else {
            continue;
        };
        let Some(entity) = entities.get(&book.entity_id) else {
            continue;
        };
        let pack = rule_pack_for(entity);
        let has_error = pack
            .check_act(act, entity)
            .iter()
            .any(|issue| issue.severity == Severity::Error);
        if has_error {
            alerts.push(DashboardAlert {
                code: "act.compliance.review_required".to_owned(),
                label: "ReviewRequired".to_owned(),
                severity: "Warning".to_owned(),
                category: "Compliance".to_owned(),
                message: format!(
                    "Act {} is in Signing and has review-required compliance findings. Review the compliance report before sealing.",
                    act.id
                ),
                params: dashboard_alert_params([
                    ("act_id", act.id.to_string()),
                    ("book_id", book.id.to_string()),
                    ("entity_id", entity.id.to_string()),
                    ("rule_pack", pack.id().to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(entity.id.to_string()),
                    book_id: Some(book.id.to_string()),
                    act_id: Some(act.id.to_string()),
                    links: target_links(Some(entity.id), Some(book.id), Some(act.id)),
                },
                source: Some(pack.id().to_owned()),
                law_refs: Vec::new(),
                action: Some(dashboard_action(
                    "open_act",
                    "notifications.alert.act.compliance.action",
                    Some(format!("/v1/acts/{}", act.id)),
                    Some(format!("/atas/{}", act.id)),
                )),
                recommended_next_steps: vec![
                    "Open the minutes compliance report.".to_owned(),
                    "Resolve review-required findings before sealing.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.act.compliance.title",
                    "notifications.alert.act.compliance.body",
                    Some("notifications.alert.act.compliance.action"),
                )),
            });
        } else {
            alerts.push(DashboardAlert {
                code: "act.lifecycle.signing_ready".to_owned(),
                label: "Advisory".to_owned(),
                severity: "Info".to_owned(),
                category: "ActLifecycle".to_owned(),
                message: format!(
                    "Act {} is in Signing and has no review-required compliance findings from rule pack {}. Collect or import the required signatures and seal when ready.",
                    act.id,
                    pack.id()
                ),
                params: dashboard_alert_params([
                    ("act_id", act.id.to_string()),
                    ("book_id", book.id.to_string()),
                    ("entity_id", entity.id.to_string()),
                    ("current_state", format!("{:?}", act.state)),
                    ("rule_pack", pack.id().to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(entity.id.to_string()),
                    book_id: Some(book.id.to_string()),
                    act_id: Some(act.id.to_string()),
                    links: target_links(Some(entity.id), Some(book.id), Some(act.id)),
                },
                source: Some("acts.state".to_owned()),
                law_refs: Vec::new(),
                action: Some(dashboard_action(
                    "open_act",
                    "notifications.alert.act.signingReady.action",
                    Some(format!("/v1/acts/{}", act.id)),
                    Some(format!("/atas/{}", act.id)),
                )),
                recommended_next_steps: vec![
                    "Collect or import required signatures.".to_owned(),
                    "Seal the minutes when the signing record is complete.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.act.signingReady.title",
                    "notifications.alert.act.signingReady.body",
                    Some("notifications.alert.act.signingReady.action"),
                )),
            });
        }
    }

    for (entity_id, extract) in registry_extracts {
        let Some(valid_until) = extract.provenance.valid_until.as_deref() else {
            continue;
        };
        let Some(valid_until_date) = parse_dashboard_date(valid_until) else {
            continue;
        };
        let days_until = valid_until_date.to_julian_day() - today.to_julian_day();
        let (code, label, message) = if compute_expired(Some(valid_until), today) == Some(true) {
            (
                "registry.provenance.expired",
                "Advisory",
                format!(
                    "Stored registry extract provenance has valid_until {valid_until}, which is before today. Review the registry extract before using it as current evidence."
                ),
            )
        } else if days_until <= REGISTRY_EXPIRY_WARNING_DAYS {
            let timing = match days_until {
                0 => "today".to_owned(),
                1 => "in 1 day".to_owned(),
                n => format!("in {n} days"),
            };
            (
                "registry.provenance.expiring_soon",
                "Advisory",
                format!(
                    "Stored registry extract provenance has valid_until {valid_until}, which expires {timing}. Plan a registry refresh before relying on it as current evidence."
                ),
            )
        } else {
            continue;
        };
        alerts.push(DashboardAlert {
            code: code.to_owned(),
            label: label.to_owned(),
            severity: "Info".to_owned(),
            category: "RegistryProvenance".to_owned(),
            message,
            params: dashboard_alert_params([
                ("entity_id", entity_id.to_string()),
                ("valid_until", valid_until.to_owned()),
                ("days_until", days_until.to_string()),
            ]),
            target: DashboardAlertTarget {
                entity_id: Some(entity_id.to_string()),
                book_id: None,
                act_id: None,
                links: target_links(Some(*entity_id), None, None),
            },
            source: Some("registry_extracts.provenance.valid_until".to_owned()),
            law_refs: Vec::new(),
            action: Some(dashboard_action(
                "open_entity",
                if code == "registry.provenance.expired" {
                    "notifications.alert.registry.expired.action"
                } else {
                    "notifications.alert.registry.expiringSoon.action"
                },
                Some(format!("/v1/entities/{entity_id}")),
                Some(format!("/entidades/{entity_id}")),
            )),
            recommended_next_steps: vec![
                "Open the entity registry evidence.".to_owned(),
                "Refresh the permanent certificate before using it as current evidence.".to_owned(),
            ],
            i18n: Some(if code == "registry.provenance.expired" {
                alert_i18n(
                    "notifications.alert.registry.expired.title",
                    "notifications.alert.registry.expired.body",
                    Some("notifications.alert.registry.expired.action"),
                )
            } else {
                alert_i18n(
                    "notifications.alert.registry.expiringSoon.title",
                    "notifications.alert.registry.expiringSoon.body",
                    Some("notifications.alert.registry.expiringSoon.action"),
                )
            }),
        });
    }

    alerts.sort_by(|a, b| {
        a.label
            .cmp(&b.label)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.target.entity_id.cmp(&b.target.entity_id))
            .then_with(|| a.target.book_id.cmp(&b.target.book_id))
            .then_with(|| a.target.act_id.cmp(&b.target.act_id))
    });
    alerts
}

fn push_lifecycle_alerts(
    alerts: &mut Vec<DashboardAlert>,
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    registry_extracts: &HashMap<EntityId, RegistryExtract>,
) {
    for entity in entities.values() {
        let total_books = books
            .values()
            .filter(|book| book.entity_id == entity.id)
            .count();
        let open_books = books
            .values()
            .filter(|book| book.entity_id == entity.id && book.state == BookState::Open)
            .count();
        if open_books == 0 {
            alerts.push(DashboardAlert {
                code: "entity.book.no_open_book".to_owned(),
                label: "Advisory".to_owned(),
                severity: "Info".to_owned(),
                category: "BookLifecycle".to_owned(),
                message: format!(
                    "Entity {} has no open book recorded. Open a book or import an existing book before drafting new atas.",
                    entity.name
                ),
                params: dashboard_alert_params([
                    ("entity_id", entity.id.to_string()),
                    ("entity_name", entity.name.clone()),
                    ("total_books", total_books.to_string()),
                    ("open_books", open_books.to_string()),
                    ("recommended_actions", "open_book,import_book".to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(entity.id.to_string()),
                    book_id: None,
                    act_id: None,
                    links: target_links(Some(entity.id), None, None),
                },
                source: Some("entities.books".to_owned()),
                law_refs: law_refs(&[("dl-76-a-2006", "1"), ("dl-76-a-2006", "2")]),
                action: Some(dashboard_action(
                    "open_entity",
                    "notifications.alert.entity.noOpenBook.action",
                    Some(format!("/v1/entities/{}", entity.id)),
                    Some(format!("/entidades/{}", entity.id)),
                )),
                recommended_next_steps: vec![
                    "Open a new digital book for the relevant organ.".to_owned(),
                    "Import an existing paper or external book if the entity already has one.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.entity.noOpenBook.title",
                    "notifications.alert.entity.noOpenBook.body",
                    Some("notifications.alert.entity.noOpenBook.action"),
                )),
            });
        }

        if should_prompt_manager_remuneration(
            entity,
            acts,
            books,
            registry_extracts.get(&entity.id),
        ) {
            alerts.push(DashboardAlert {
                code: "entity.manager_remuneration.setup_recommended".to_owned(),
                label: "Advisory".to_owned(),
                severity: "Info".to_owned(),
                category: "GovernanceSetup".to_owned(),
                message: format!(
                    "Entity {} has management/administration officers in the imported registry evidence, but no sealed remuneration or non-remuneration minutes are recorded. Record the remuneration setup when appropriate.",
                    entity.name
                ),
                params: dashboard_alert_params([
                    ("entity_id", entity.id.to_string()),
                    ("entity_name", entity.name.clone()),
                    ("recommended_actions", "record_remuneration,record_non_remuneration".to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(entity.id.to_string()),
                    book_id: None,
                    act_id: None,
                    links: target_links(Some(entity.id), None, None),
                },
                source: Some("registry_extracts.orgaos".to_owned()),
                law_refs: remuneration_law_refs(entity.kind),
                action: Some(dashboard_action(
                    "open_entity",
                    "notifications.alert.entity.managerRemuneration.action",
                    Some(format!("/v1/entities/{}", entity.id)),
                    Some(format!("/entidades/{}", entity.id)),
                )),
                recommended_next_steps: vec![
                    "Review the registry officers and statutes.".to_owned(),
                    "Draft minutes for remuneration or explicit non-remuneration if required.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.entity.managerRemuneration.title",
                    "notifications.alert.entity.managerRemuneration.body",
                    Some("notifications.alert.entity.managerRemuneration.action"),
                )),
            });
        }
    }

    for book in books.values().filter(|book| book.state == BookState::Open) {
        let missing_fields = termo_abertura_missing_fields(book);
        if !missing_fields.is_empty() {
            alerts.push(DashboardAlert {
                code: "book.termo_abertura.missing_metadata".to_owned(),
                label: "ReviewRequired".to_owned(),
                severity: "Warning".to_owned(),
                category: "BookLifecycle".to_owned(),
                message: format!(
                    "Open book {} is missing termo de abertura metadata or signatories. Review the book opening record before relying on it as complete evidence.",
                    book.id
                ),
                params: dashboard_alert_params([
                    ("book_id", book.id.to_string()),
                    ("entity_id", book.entity_id.to_string()),
                    ("book_kind", format!("{:?}", book.kind)),
                    ("missing_fields", missing_fields.join(",")),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(book.entity_id.to_string()),
                    book_id: Some(book.id.to_string()),
                    act_id: None,
                    links: target_links(Some(book.entity_id), Some(book.id), None),
                },
                source: Some("books.termo_abertura".to_owned()),
                law_refs: law_refs(&[("dl-76-a-2006", "1"), ("dl-76-a-2006", "2")]),
                action: Some(dashboard_action(
                    "open_book",
                    "notifications.alert.book.missingTermo.action",
                    Some(format!("/v1/books/{}", book.id)),
                    Some(format!("/livros/{}", book.id)),
                )),
                recommended_next_steps: vec![
                    "Complete the opening term identification and purpose metadata.".to_owned(),
                    "Record the required signatories for the book opening.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.book.missingTermo.title",
                    "notifications.alert.book.missingTermo.body",
                    Some("notifications.alert.book.missingTermo.action"),
                )),
            });
        }

        let act_count = acts.values().filter(|act| act.book_id == book.id).count();
        if act_count == 0 {
            alerts.push(DashboardAlert {
                code: "book.acts.none_recorded".to_owned(),
                label: "Advisory".to_owned(),
                severity: "Info".to_owned(),
                category: "BookLifecycle".to_owned(),
                message: format!(
                    "Open book {} has no acts recorded yet. Draft a new ata or import historical minutes when appropriate.",
                    book.id
                ),
                params: dashboard_alert_params([
                    ("book_id", book.id.to_string()),
                    ("entity_id", book.entity_id.to_string()),
                    ("book_kind", format!("{:?}", book.kind)),
                    (
                        "next_ata_number",
                        book.last_ata_number.saturating_add(1).to_string(),
                    ),
                    ("recommended_actions", "draft_ata,import_minutes".to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(book.entity_id.to_string()),
                    book_id: Some(book.id.to_string()),
                    act_id: None,
                    links: target_links(Some(book.entity_id), Some(book.id), None),
                },
                source: Some("acts.by_book".to_owned()),
                law_refs: law_refs(&[("dl-76-a-2006", "1"), ("dl-76-a-2006", "2")]),
                action: Some(dashboard_action(
                    "open_book",
                    "notifications.alert.book.noActs.action",
                    Some(format!("/v1/books/{}", book.id)),
                    Some(format!("/livros/{}", book.id)),
                )),
                recommended_next_steps: vec![
                    "Draft the next minutes for this book.".to_owned(),
                    "Import historical minutes if this book is being migrated.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.book.noActs.title",
                    "notifications.alert.book.noActs.body",
                    Some("notifications.alert.book.noActs.action"),
                )),
            });
        }
    }

    for act in acts.values() {
        let Some(next_state) = next_act_state(act.state) else {
            continue;
        };
        let Some(book) = books.get(&act.book_id) else {
            continue;
        };
        let entity_id = book.entity_id;
        alerts.push(DashboardAlert {
            code: "act.lifecycle.advance_available".to_owned(),
            label: "Advisory".to_owned(),
            severity: "Info".to_owned(),
            category: "ActLifecycle".to_owned(),
            message: format!(
                "Act {} is in {:?}. Continue the recorded lifecycle and advance to {:?} when the supporting work is ready.",
                act.id, act.state, next_state
            ),
            params: dashboard_alert_params([
                ("act_id", act.id.to_string()),
                ("book_id", book.id.to_string()),
                ("entity_id", entity_id.to_string()),
                ("current_state", format!("{:?}", act.state)),
                ("next_state", format!("{:?}", next_state)),
            ]),
            target: DashboardAlertTarget {
                entity_id: Some(entity_id.to_string()),
                book_id: Some(book.id.to_string()),
                act_id: Some(act.id.to_string()),
                links: target_links(Some(entity_id), Some(book.id), Some(act.id)),
            },
            source: Some("acts.state".to_owned()),
            law_refs: Vec::new(),
            action: Some(dashboard_action(
                "open_act",
                "notifications.alert.act.advanceAvailable.action",
                Some(format!("/v1/acts/{}", act.id)),
                Some(format!("/atas/{}", act.id)),
            )),
            recommended_next_steps: vec![
                "Review the supporting work for the current lifecycle state.".to_owned(),
                "Advance the minutes when the next state is ready.".to_owned(),
            ],
            i18n: Some(alert_i18n(
                "notifications.alert.act.advanceAvailable.title",
                "notifications.alert.act.advanceAvailable.body",
                Some("notifications.alert.act.advanceAvailable.action"),
            )),
        });
    }
}

fn termo_abertura_missing_fields(book: &Book) -> Vec<&'static str> {
    let Some(termo) = book.termo_abertura.as_ref() else {
        return vec!["termo_abertura"];
    };

    let mut missing = Vec::new();
    if termo.entity_name.trim().is_empty() {
        missing.push("entity_name");
    }
    if termo.entity_nipc.trim().is_empty() {
        missing.push("entity_nipc");
    }
    if termo.entity_seat.trim().is_empty() {
        missing.push("entity_seat");
    }
    if termo.purpose.trim().is_empty() {
        missing.push("purpose");
    }
    if termo
        .required_signatories
        .iter()
        .all(|signatory| signatory.trim().is_empty())
    {
        missing.push("required_signatories");
    }
    missing
}

fn next_act_state(state: ActState) -> Option<ActState> {
    match state {
        ActState::Draft => Some(ActState::Review),
        ActState::Review => Some(ActState::Convened),
        ActState::Convened => Some(ActState::Deliberated),
        ActState::Deliberated => Some(ActState::TextApproved),
        ActState::TextApproved => Some(ActState::Signing),
        ActState::Signing | ActState::Sealed | ActState::Archived => None,
    }
}

fn dashboard_alert_params<const N: usize>(
    entries: [(&str, String); N],
) -> BTreeMap<String, String> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn alert_i18n(title_key: &str, body_key: &str, action_key: Option<&str>) -> DashboardI18n {
    DashboardI18n {
        title_key: title_key.to_owned(),
        body_key: body_key.to_owned(),
        action_key: action_key.map(str::to_owned),
    }
}

fn dashboard_action(
    kind: &str,
    label_key: &str,
    api_href: Option<String>,
    route: Option<String>,
) -> DashboardAction {
    DashboardAction {
        kind: kind.to_owned(),
        label_key: label_key.to_owned(),
        api_href,
        route,
    }
}

fn law_refs(refs: &[(&str, &str)]) -> Vec<DashboardLawReference> {
    let catalog = LawCatalog::embedded();
    refs.iter()
        .map(|(diploma_id, article_number)| {
            catalog
                .article(diploma_id, article_number)
                .map(|article| DashboardLawReference {
                    diploma_id: article.diploma_id.clone(),
                    article: article.number.clone(),
                    label: article.label.clone(),
                    heading: article.heading.clone(),
                    verification: format!("{:?}", article.verification),
                    source_url: article.source.url.clone(),
                })
                .unwrap_or_else(|| DashboardLawReference {
                    diploma_id: (*diploma_id).to_owned(),
                    article: (*article_number).to_owned(),
                    label: format!("Artigo {article_number}"),
                    heading: String::new(),
                    verification: "Missing".to_owned(),
                    source_url: None,
                })
        })
        .collect()
}

fn remuneration_law_refs(kind: EntityKind) -> Vec<DashboardLawReference> {
    if matches!(kind, EntityKind::SociedadeAnonima) {
        law_refs(&[("csc", "399")])
    } else {
        law_refs(&[("csc", "255")])
    }
}

fn should_prompt_manager_remuneration(
    entity: &Entity,
    acts: &HashMap<ActId, Act>,
    books: &HashMap<BookId, Book>,
    registry_extract: Option<&RegistryExtract>,
) -> bool {
    if !matches!(entity.family, EntityFamily::CommercialCompany) || !is_sa_or_lda_like(entity.kind)
    {
        return false;
    }
    let Some(extract) = registry_extract else {
        return false;
    };
    if !extract.orgaos.iter().any(|officer| {
        officer.cessation_date.is_none()
            && officer
                .role
                .as_deref()
                .map(fold_ascii)
                .is_some_and(|role| role.contains("gerente") || role.contains("administrador"))
    }) {
        return false;
    }

    !acts.values().any(|act| {
        matches!(act.state, ActState::Sealed | ActState::Archived)
            && books
                .get(&act.book_id)
                .is_some_and(|book| book.entity_id == entity.id)
            && act_mentions_remuneration(act)
    })
}

fn act_mentions_remuneration(act: &Act) -> bool {
    let haystack = fold_ascii(&format!("{} {}", act.title, act.deliberations));
    haystack.contains("remuneracao") || haystack.contains("nao remuneracao")
}

fn fold_ascii(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'u',
            'ç' | 'Ç' => 'c',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

fn parse_dashboard_date(value: &str) -> Option<Date> {
    let (year, rest) = value.split_once('-')?;
    let (month, day) = rest.split_once('-')?;
    let year = year.parse::<i32>().ok()?;
    let month = Month::try_from(month.parse::<u8>().ok()?).ok()?;
    let day = day.parse::<u8>().ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

fn target_links(
    entity_id: Option<EntityId>,
    book_id: Option<BookId>,
    act_id: Option<ActId>,
) -> DashboardTargetLinks {
    DashboardTargetLinks {
        entity: entity_id.map(|id| format!("/v1/entities/{id}")),
        book: book_id.map(|id| format!("/v1/books/{id}")),
        act: act_id.map(|id| format!("/v1/acts/{id}")),
        ledger: ledger_link(entity_id, book_id, act_id),
    }
}

fn ledger_link(
    entity_id: Option<EntityId>,
    book_id: Option<BookId>,
    act_id: Option<ActId>,
) -> Option<String> {
    if let Some(act_id) = act_id {
        return Some(format!("/v1/ledger/events?scope=act:{act_id}"));
    }
    if let Some(book_id) = book_id {
        return Some(format!("/v1/ledger/events?chain=book:{book_id}"));
    }
    entity_id.map(|id| format!("/v1/ledger/events?chain=company:{id}"))
}

fn dashboard_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    registry_extracts: &HashMap<EntityId, RegistryExtract>,
    today: Date,
) -> Vec<DashboardReminder> {
    let mut reminders = entities
        .values()
        .flat_map(|entity| {
            annual_general_meeting_reminders(
                entity,
                books,
                acts,
                registry_extracts.get(&entity.id),
                today,
            )
        })
        .collect::<Vec<_>>();

    reminders.sort_by(|a, b| {
        a.due_date
            .cmp(&b.due_date)
            .then_with(|| a.entity_name.cmp(&b.entity_name))
            .then_with(|| a.entity_id.cmp(&b.entity_id))
            .then_with(|| a.source_profile.cmp(&b.source_profile))
            .then_with(|| a.source_rule.cmp(&b.source_rule))
    });
    reminders.truncate(DASHBOARD_REMINDER_LIMIT);
    reminders
}

fn annual_general_meeting_reminders(
    entity: &Entity,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    registry_extract: Option<&RegistryExtract>,
    today: Date,
) -> Vec<DashboardReminder> {
    if !entity.is_consistent() || !supports_profile_calendar_reminders(entity) {
        return Vec::new();
    }

    let profile = profile_for(entity.kind);
    profile
        .calendar_presets
        .iter()
        .filter_map(|preset| {
            profile_calendar_reminder(
                entity,
                &profile,
                preset,
                books,
                acts,
                registry_extract,
                today,
            )
        })
        .collect()
}

fn profile_calendar_reminder(
    entity: &Entity,
    profile: &EntityProfile,
    preset: &CalendarPreset,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    registry_extract: Option<&RegistryExtract>,
    today: Date,
) -> Option<DashboardReminder> {
    let months_after_fiscal_year_end = preset.months_after_fiscal_year_end?;

    let parsed_fiscal_year_end = parse_fiscal_year_end(entity.fiscal_year_end.as_deref());
    let fiscal_year_end = parsed_fiscal_year_end.unwrap_or(DEFAULT_FISCAL_YEAR_END);
    let due_date =
        annual_due_date_for_year(today.year(), fiscal_year_end, months_after_fiscal_year_end);
    if is_before_first_applicable_annual_due(
        registry_extract,
        fiscal_year_end,
        months_after_fiscal_year_end,
        due_date,
    ) {
        return None;
    }
    if has_recent_calendar_signal(entity, books, acts, due_date.year()) {
        return None;
    }

    let fiscal_year_note = match (
        entity.fiscal_year_end.as_deref(),
        parsed_fiscal_year_end.is_some(),
    ) {
        (Some(_), true) => "using the entity's recorded fiscal_year_end",
        (Some(_), false) => {
            "using the default Dec 31 fiscal-year end because the recorded fiscal_year_end could not be read"
        }
        (None, _) => {
            "using the default Dec 31 fiscal-year end because no fiscal_year_end is recorded"
        }
    };
    Some(DashboardReminder {
        due_date: format_date(due_date),
        severity: "Advisory".to_owned(),
        status: reminder_status(today, due_date).to_owned(),
        reason: format!(
            "The {} calendar preset \"{}\" points to an annual item by {} \
             ({fiscal_year_note}). \
             No sealed or archived {} act dated {} is recorded for this entity. \
             Chancela cannot yet prove this annual calendar purpose, so this is advisory.",
            family_calendar_label(profile.family),
            preset.label,
            format_date(due_date),
            calendar_signal_label(profile.family),
            due_date.year()
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: preset.id.to_owned(),
        source_profile: profile.template_family.to_owned(),
        law_refs: calendar_law_refs(profile.family, preset.id),
        action: Some(dashboard_action(
            "open_entity",
            "notifications.reminder.annual.action",
            Some(format!("/v1/entities/{}", entity.id)),
            Some(format!("/entidades/{}", entity.id)),
        )),
        recommended_next_steps: calendar_next_steps(profile.family),
    })
}

fn calendar_law_refs(family: EntityFamily, preset_id: &str) -> Vec<DashboardLawReference> {
    match (family, preset_id) {
        (EntityFamily::CommercialCompany, "csc-art376-annual") => law_refs(&[("csc", "376")]),
        (EntityFamily::Association, "assoc-annual") => law_refs(&[("cc", "173")]),
        (EntityFamily::Cooperative, "cooperativa-annual") => law_refs(&[("cod-cooperativo", "33")]),
        _ => Vec::new(),
    }
}

fn calendar_next_steps(family: EntityFamily) -> Vec<String> {
    match family {
        EntityFamily::CommercialCompany => vec![
            "Prepare annual accounts approval minutes if the meeting has not occurred.".to_owned(),
            "Seal or archive the annual general meeting minutes once approved.".to_owned(),
        ],
        EntityFamily::Association | EntityFamily::Cooperative => vec![
            "Prepare the annual general meeting record if the meeting has not occurred.".to_owned(),
            "Seal or archive the annual minutes once approved.".to_owned(),
        ],
        EntityFamily::Foundation => vec![
            "Review the annual foundation governance record.".to_owned(),
            "Seal or archive the relevant annual act once approved.".to_owned(),
        ],
        EntityFamily::Condominium => vec![
            "Review the annual condominium assembly record.".to_owned(),
            "Seal or archive the assembly minutes once approved.".to_owned(),
        ],
    }
}

fn supports_profile_calendar_reminders(entity: &Entity) -> bool {
    !matches!(entity.family, EntityFamily::CommercialCompany) || is_sa_or_lda_like(entity.kind)
}

fn is_sa_or_lda_like(kind: EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::SociedadeAnonima
            | EntityKind::SociedadePorQuotas
            | EntityKind::SociedadeUnipessoalPorQuotas
    )
}

fn family_calendar_label(family: EntityFamily) -> &'static str {
    match family {
        EntityFamily::CommercialCompany => "commercial-company",
        EntityFamily::Condominium => "condominium",
        EntityFamily::Association => "association",
        EntityFamily::Foundation => "foundation",
        EntityFamily::Cooperative => "cooperative",
    }
}

fn calendar_signal_label(family: EntityFamily) -> &'static str {
    match family {
        EntityFamily::CommercialCompany | EntityFamily::Association | EntityFamily::Cooperative => {
            "Assembleia Geral"
        }
        EntityFamily::Condominium => "condominium assembly",
        EntityFamily::Foundation => "administration/assembly",
    }
}

const DEFAULT_FISCAL_YEAR_END: FiscalYearEnd = FiscalYearEnd { month: 12, day: 31 };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FiscalYearEnd {
    month: u8,
    day: u8,
}

fn parse_fiscal_year_end(value: Option<&str>) -> Option<FiscalYearEnd> {
    let value = value?;
    let (month, day) = value.split_once('-')?;
    let month = month.parse::<u8>().ok()?;
    let day = day.parse::<u8>().ok()?;
    let month = Month::try_from(month).ok()?;
    Date::from_calendar_date(2000, month, day).ok()?;
    Some(FiscalYearEnd {
        month: month as u8,
        day,
    })
}

fn annual_due_date_for_year(
    due_year: i32,
    fiscal_year_end: FiscalYearEnd,
    months_after_fiscal_year_end: u8,
) -> Date {
    for fiscal_year in [due_year, due_year - 1] {
        let due_date = add_months_clamped(
            fiscal_year_end_date(fiscal_year, fiscal_year_end),
            months_after_fiscal_year_end,
        );
        if due_date.year() == due_year {
            return due_date;
        }
    }
    add_months_clamped(
        fiscal_year_end_date(due_year, fiscal_year_end),
        months_after_fiscal_year_end,
    )
}

fn is_before_first_applicable_annual_due(
    registry_extract: Option<&RegistryExtract>,
    fiscal_year_end: FiscalYearEnd,
    months_after_fiscal_year_end: u8,
    due_date: Date,
) -> bool {
    let Some(constitution_date) = registry_extract
        .and_then(|extract| extract.data_constituicao.as_deref())
        .and_then(parse_dashboard_date)
    else {
        // Conservative fallback: without a registry constitution/incorporation date, keep the
        // annual dashboard reminder rather than guessing that the company is still first-year.
        return false;
    };
    due_date
        < first_applicable_annual_due_date(
            constitution_date,
            fiscal_year_end,
            months_after_fiscal_year_end,
        )
}

fn first_applicable_annual_due_date(
    constitution_date: Date,
    fiscal_year_end: FiscalYearEnd,
    months_after_fiscal_year_end: u8,
) -> Date {
    let constitution_year_end = fiscal_year_end_date(constitution_date.year(), fiscal_year_end);
    let first_fiscal_year_end = if constitution_year_end >= constitution_date {
        constitution_year_end
    } else {
        fiscal_year_end_date(constitution_date.year() + 1, fiscal_year_end)
    };
    add_months_clamped(first_fiscal_year_end, months_after_fiscal_year_end)
}

fn fiscal_year_end_date(year: i32, fiscal_year_end: FiscalYearEnd) -> Date {
    let month = Month::try_from(fiscal_year_end.month).expect("validated fiscal year end month");
    let day = fiscal_year_end
        .day
        .min(days_in_month(year, fiscal_year_end.month));
    Date::from_calendar_date(year, month, day).expect("clamped fiscal year end date is valid")
}

fn add_months_clamped(date: Date, months: u8) -> Date {
    let zero_based_month = date.month() as i32 - 1 + i32::from(months);
    let year = date.year() + zero_based_month.div_euclid(12);
    let month = zero_based_month.rem_euclid(12) as u8 + 1;
    let day = date.day().min(days_in_month(year, month));
    Date::from_calendar_date(
        year,
        Month::try_from(month).expect("computed month is valid"),
        day,
    )
    .expect("clamped due date is valid")
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => unreachable!("month has already been validated"),
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn reminder_status(today: Date, due_date: Date) -> &'static str {
    if today > due_date {
        return "Overdue";
    }
    let days_until = due_date.ordinal() as i32 - today.ordinal() as i32;
    if days_until <= 45 {
        "DueSoon"
    } else {
        "Upcoming"
    }
}

fn has_recent_calendar_signal(
    entity: &Entity,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    due_year: i32,
) -> bool {
    let signal_book_kinds = calendar_signal_book_kinds(entity.family);
    acts.values().any(|act| {
        let Some(book) = books.get(&act.book_id) else {
            return false;
        };
        book.entity_id == entity.id
            && signal_book_kinds.contains(&book.kind)
            && matches!(act.state, ActState::Sealed | ActState::Archived)
            && act
                .meeting_date
                .is_some_and(|meeting_date| meeting_date.year() == due_year)
    })
}

fn calendar_signal_book_kinds(family: EntityFamily) -> &'static [BookKind] {
    match family {
        EntityFamily::CommercialCompany | EntityFamily::Association | EntityFamily::Cooperative => {
            &[BookKind::AssembleiaGeral]
        }
        EntityFamily::Condominium => &[BookKind::Condominio],
        // Foundation templates model the annual board spine, while legacy/test data may still use
        // the general-assembly book as the shared family ata container.
        EntityFamily::Foundation => &[BookKind::GerenciaAdministracao, BookKind::AssembleiaGeral],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_core::{MeetingChannel, Nipc, NumberingScheme, TermoDeAbertura};
    use chancela_registry::{RegistryExtract, RegistryOfficer, RegistryProvenance};
    use time::macros::date;

    fn entity_of(kind: EntityKind) -> Entity {
        Entity::new(
            "Encosto Estrategico, S.A.",
            Nipc::parse("503004642").unwrap(),
            "Lisboa",
            kind,
        )
    }

    fn named_entity(kind: EntityKind, name: &str, id: &str) -> Entity {
        let mut entity = Entity::new(name, Nipc::unvalidated(id), "Lisboa", kind);
        entity.id = EntityId(uuid::Uuid::parse_str(id).unwrap());
        entity
    }

    fn registry_extract(valid_until: Option<&str>) -> RegistryExtract {
        RegistryExtract {
            matricula: None,
            nipc: None,
            firma: None,
            forma_juridica: None,
            legal_form: None,
            sede: None,
            cae: Vec::new(),
            objeto: None,
            capital: None,
            data_constituicao: None,
            orgaos: Vec::new(),
            inscricoes: Vec::new(),
            anotacoes: Vec::new(),
            provenance: RegistryProvenance {
                access_code_masked: "****-****-9012".to_owned(),
                retrieved_at: "2026-07-01T00:00:00Z".to_owned(),
                source_url: "mock://registry/certidao".to_owned(),
                raw_digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_owned(),
                conservatoria: None,
                oficial: None,
                subscribed_on: Some("2025-07-01".to_owned()),
                valid_until: valid_until.map(str::to_owned),
            },
        }
    }

    fn registry_extract_with_constitution_date(constitution_date: &str) -> RegistryExtract {
        let mut extract = registry_extract(None);
        extract.data_constituicao = Some(constitution_date.to_owned());
        extract
    }

    fn registry_extract_with_officer(role: &str) -> RegistryExtract {
        let mut extract = registry_extract(None);
        extract.orgaos.push(RegistryOfficer {
            name: "Maria Gestora".to_owned(),
            role: Some(role.to_owned()),
            appointment_date: Some("2026-01-10".to_owned()),
            cessation_date: None,
            source_event: Some("1".to_owned()),
        });
        extract
    }

    #[test]
    fn current_work_reports_open_books_and_exact_act_states() {
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Open;
        book.last_ata_number = 7;
        book.termo_abertura = Some(TermoDeAbertura {
            entity_name: entity.name.clone(),
            entity_nipc: entity.nipc.as_str().to_owned(),
            entity_seat: entity.seat.clone(),
            purpose: "Livro de atas da assembleia geral".to_owned(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: date!(2026 - 01 - 05),
            required_signatories: vec!["Gerência".to_owned()],
        });

        let draft = Act::draft(book.id, "Rascunho", MeetingChannel::Physical);
        let mut signing = Act::draft(book.id, "Assinatura", MeetingChannel::Physical);
        signing.state = ActState::Signing;
        let mut archived = Act::draft(book.id, "Arquivo", MeetingChannel::Physical);
        archived.state = ActState::Archived;

        let entities = HashMap::from([(entity.id, entity.clone())]);
        let books = HashMap::from([(book.id, book.clone())]);
        let acts = HashMap::from([
            (draft.id, draft),
            (signing.id, signing),
            (archived.id, archived),
        ]);

        let current = dashboard_current_work(&entities, &books, &acts);

        assert_eq!(current.act_counts_by_state.draft, 1);
        assert_eq!(current.act_counts_by_state.signing, 1);
        assert_eq!(current.act_counts_by_state.archived, 1);
        assert_eq!(current.open_books.len(), 1);
        let row = &current.open_books[0];
        assert_eq!(row.book_id, book.id.to_string());
        assert_eq!(row.entity_id, entity.id.to_string());
        assert_eq!(row.entity_name.as_deref(), Some(entity.name.as_str()));
        assert_eq!(row.kind, BookKind::AssembleiaGeral);
        assert_eq!(
            row.purpose.as_deref(),
            Some("Livro de atas da assembleia geral")
        );
        assert_eq!(row.opening_date.as_deref(), Some("2026-01-05"));
        assert_eq!(row.last_ata_number, 7);
        assert_eq!(row.next_ata_number, 8);
        assert_eq!(row.total_acts, 3);
        assert_eq!(row.open_acts, 2);
        let expected_entity_link = format!("/v1/entities/{}", entity.id);
        let expected_book_link = format!("/v1/books/{}", book.id);
        assert_eq!(
            row.links.entity.as_deref(),
            Some(expected_entity_link.as_str())
        );
        assert_eq!(row.links.book.as_deref(), Some(expected_book_link.as_str()));
    }

    #[test]
    fn registry_validity_alerts_cover_expiring_and_expired_codes() {
        let expired_id =
            EntityId(uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000201").unwrap());
        let expiring_id =
            EntityId(uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000202").unwrap());
        let fresh_id =
            EntityId(uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000203").unwrap());
        let registry_extracts = HashMap::from([
            (expired_id, registry_extract(Some("2026-07-08"))),
            (expiring_id, registry_extract(Some("2026-08-01"))),
            (fresh_id, registry_extract(Some("2026-12-31"))),
        ]);

        let alerts = dashboard_alerts(
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &registry_extracts,
            true,
            date!(2026 - 07 - 09),
        );

        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().any(|alert| {
            alert.code == "registry.provenance.expired"
                && alert.target.entity_id.as_deref() == Some(&expired_id.to_string())
                && alert.message.contains("before today")
        }));
        assert!(alerts.iter().any(|alert| {
            alert.code == "registry.provenance.expiring_soon"
                && alert.target.entity_id.as_deref() == Some(&expiring_id.to_string())
                && alert.message.contains("expires in 23 days")
        }));
    }

    #[test]
    fn lifecycle_alerts_cover_entity_without_open_book() {
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let entities = HashMap::from([(entity.id, entity.clone())]);

        let alerts = dashboard_alerts(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            true,
            date!(2026 - 07 - 09),
        );

        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.code, "entity.book.no_open_book");
        assert_eq!(alert.label, "Advisory");
        assert_eq!(alert.category, "BookLifecycle");
        let expected_entity_id = entity.id.to_string();
        let expected_entity_link = format!("/v1/entities/{}", entity.id);
        let expected_ledger_link = format!("/v1/ledger/events?chain=company:{}", entity.id);
        assert_eq!(alert.params.get("entity_id"), Some(&expected_entity_id));
        assert_eq!(
            alert.params.get("total_books").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            alert.params.get("open_books").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            alert.params.get("recommended_actions").map(String::as_str),
            Some("open_book,import_book")
        );
        assert_eq!(
            alert.target.entity_id.as_deref(),
            Some(expected_entity_id.as_str())
        );
        assert_eq!(alert.target.book_id, None);
        assert_eq!(alert.target.act_id, None);
        assert_eq!(
            alert.target.links.entity.as_deref(),
            Some(expected_entity_link.as_str())
        );
        assert_eq!(
            alert.target.links.ledger.as_deref(),
            Some(expected_ledger_link.as_str())
        );
        assert_eq!(alert.severity, "Info");
        assert_eq!(alert.law_refs[0].diploma_id, "dl-76-a-2006");
        assert_eq!(
            alert.action.as_ref().map(|action| action.kind.as_str()),
            Some("open_entity")
        );
        assert!(
            alert
                .recommended_next_steps
                .iter()
                .any(|step| step.contains("Open a new digital book"))
        );
    }

    #[test]
    fn lifecycle_alerts_recommend_manager_remuneration_setup_from_registry_officers() {
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let entities = HashMap::from([(entity.id, entity.clone())]);
        let registry_extracts =
            HashMap::from([(entity.id, registry_extract_with_officer("Gerente"))]);

        let alerts = dashboard_alerts(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &registry_extracts,
            true,
            date!(2026 - 07 - 09),
        );

        let alert = alerts
            .iter()
            .find(|alert| alert.code == "entity.manager_remuneration.setup_recommended")
            .expect("manager remuneration alert");
        assert_eq!(alert.severity, "Info");
        assert_eq!(alert.category, "GovernanceSetup");
        assert_eq!(alert.law_refs.len(), 1);
        assert_eq!(alert.law_refs[0].diploma_id, "csc");
        assert_eq!(alert.law_refs[0].article, "255");
        let expected_route = format!("/entidades/{}", entity.id);
        assert_eq!(
            alert
                .action
                .as_ref()
                .and_then(|action| action.route.as_deref()),
            Some(expected_route.as_str())
        );
        assert_eq!(
            alert.params.get("recommended_actions").map(String::as_str),
            Some("record_remuneration,record_non_remuneration")
        );
    }

    #[test]
    fn manager_remuneration_setup_alert_is_suppressed_by_sealed_remuneration_minutes() {
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = Book::new(entity.id, BookKind::AssembleiaGeral);
        let mut act = Act::draft(
            book.id,
            "Ata de não remuneração da gerência",
            MeetingChannel::Physical,
        );
        act.state = ActState::Sealed;

        let alerts = dashboard_alerts(
            &HashMap::from([(entity.id, entity.clone())]),
            &HashMap::from([(book.id, book)]),
            &HashMap::from([(act.id, act)]),
            &HashMap::from([(entity.id, registry_extract_with_officer("Gerente"))]),
            true,
            date!(2026 - 07 - 09),
        );

        assert!(
            !alerts
                .iter()
                .any(|alert| alert.code == "entity.manager_remuneration.setup_recommended")
        );
    }

    #[test]
    fn lifecycle_alerts_cover_open_book_missing_termo_metadata_and_no_acts() {
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Open;
        book.termo_abertura = Some(TermoDeAbertura {
            entity_name: "".to_owned(),
            entity_nipc: "".to_owned(),
            entity_seat: " ".to_owned(),
            purpose: "".to_owned(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: date!(2026 - 01 - 05),
            required_signatories: Vec::new(),
        });
        let entities = HashMap::from([(entity.id, entity.clone())]);
        let books = HashMap::from([(book.id, book.clone())]);

        let alerts = dashboard_alerts(
            &entities,
            &books,
            &HashMap::new(),
            &HashMap::new(),
            true,
            date!(2026 - 07 - 09),
        );

        assert_eq!(alerts.len(), 2);
        let no_acts = alerts
            .iter()
            .find(|alert| alert.code == "book.acts.none_recorded")
            .expect("no-acts alert");
        assert_eq!(no_acts.label, "Advisory");
        assert_eq!(no_acts.category, "BookLifecycle");
        let expected_entity_id = entity.id.to_string();
        let expected_book_id = book.id.to_string();
        let expected_book_link = format!("/v1/books/{}", book.id);
        let expected_book_ledger_link = format!("/v1/ledger/events?chain=book:{}", book.id);
        assert_eq!(no_acts.params.get("book_id"), Some(&expected_book_id));
        assert_eq!(no_acts.params.get("entity_id"), Some(&expected_entity_id));
        assert_eq!(
            no_acts.params.get("next_ata_number").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            no_acts
                .params
                .get("recommended_actions")
                .map(String::as_str),
            Some("draft_ata,import_minutes")
        );
        assert_eq!(
            no_acts.target.book_id.as_deref(),
            Some(expected_book_id.as_str())
        );
        assert_eq!(
            no_acts.target.links.book.as_deref(),
            Some(expected_book_link.as_str())
        );

        let missing_termo = alerts
            .iter()
            .find(|alert| alert.code == "book.termo_abertura.missing_metadata")
            .expect("missing termo alert");
        assert_eq!(missing_termo.label, "ReviewRequired");
        assert_eq!(missing_termo.category, "BookLifecycle");
        assert_eq!(
            missing_termo
                .params
                .get("missing_fields")
                .map(String::as_str),
            Some("entity_name,entity_nipc,entity_seat,purpose,required_signatories")
        );
        assert_eq!(
            missing_termo.target.links.ledger.as_deref(),
            Some(expected_book_ledger_link.as_str())
        );
    }

    #[test]
    fn missing_fiscal_year_uses_default_for_profile_calendar_reminder() {
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity.clone());

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2026 - 07 - 09),
        );

        assert_eq!(reminders.len(), 1);
        let reminder = &reminders[0];
        assert_eq!(reminder.due_date, "2026-03-31");
        assert_eq!(reminder.severity, "Advisory");
        assert_eq!(reminder.status, "Overdue");
        assert_eq!(reminder.entity_id, entity.id.to_string());
        assert_eq!(reminder.entity_name, entity.name);
        assert_eq!(reminder.source_rule, "csc-art376-annual");
        assert_eq!(reminder.source_profile, "csc-commercial");
        assert!(
            reminder
                .reason
                .contains("cannot yet prove this annual calendar purpose")
        );
        assert!(
            reminder
                .reason
                .contains("default Dec 31 fiscal-year end because no fiscal_year_end is recorded")
        );
    }

    #[test]
    fn profile_calendar_reminder_uses_recorded_fiscal_year_end() {
        let mut entity = entity_of(EntityKind::SociedadeAnonima);
        entity.fiscal_year_end = Some("08-31".to_owned());
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2026 - 07 - 09),
        );

        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].due_date, "2026-11-30");
        assert_eq!(reminders[0].status, "Upcoming");
        assert!(
            reminders[0]
                .reason
                .contains("using the entity's recorded fiscal_year_end")
        );
    }

    #[test]
    fn invalid_fiscal_year_end_falls_back_to_default_without_blocking_reminder() {
        let mut entity = entity_of(EntityKind::Associacao);
        entity.fiscal_year_end = Some("02-30".to_owned());
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2026 - 01 - 15),
        );

        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].due_date, "2026-03-31");
        assert_eq!(reminders[0].source_rule, "assoc-annual");
        assert!(
            reminders[0]
                .reason
                .contains("recorded fiscal_year_end could not be read")
        );
    }

    #[test]
    fn first_year_company_suppresses_pre_constitution_annual_reminder() {
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity.clone());
        let registry_extracts = HashMap::from([(
            entity.id,
            registry_extract_with_constitution_date("2026-01-10"),
        )]);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &registry_extracts,
            date!(2026 - 07 - 09),
        );

        assert!(
            reminders.is_empty(),
            "2026 dashboard must not report a 2025 fiscal-year annual item for a 2026 company"
        );
    }

    #[test]
    fn subsequent_year_company_still_emits_overdue_annual_reminder() {
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity.clone());
        let registry_extracts = HashMap::from([(
            entity.id,
            registry_extract_with_constitution_date("2025-01-10"),
        )]);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &registry_extracts,
            date!(2026 - 07 - 09),
        );

        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].due_date, "2026-03-31");
        assert_eq!(reminders[0].status, "Overdue");
        assert_eq!(reminders[0].source_rule, "csc-art376-annual");
        assert_eq!(reminders[0].entity_id, entity.id.to_string());
    }

    #[test]
    fn company_without_constitution_date_keeps_annual_reminder_conservatively() {
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity.clone());

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::from([(entity.id, registry_extract(None))]),
            date!(2026 - 07 - 09),
        );

        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].due_date, "2026-03-31");
        assert_eq!(reminders[0].source_rule, "csc-art376-annual");
        assert_eq!(reminders[0].entity_id, entity.id.to_string());
    }

    #[test]
    fn profile_calendar_reminders_cover_encoded_non_commercial_profiles() {
        let associacao = named_entity(
            EntityKind::Associacao,
            "Associacao Norte",
            "00000000-0000-4000-8000-000000000101",
        );
        let fundacao = named_entity(
            EntityKind::Fundacao,
            "Fundacao Centro",
            "00000000-0000-4000-8000-000000000102",
        );
        let cooperativa = named_entity(
            EntityKind::Cooperativa,
            "Cooperativa Sul",
            "00000000-0000-4000-8000-000000000103",
        );
        let mut entities = HashMap::new();
        for entity in [associacao, fundacao, cooperativa] {
            entities.insert(entity.id, entity);
        }

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2026 - 01 - 15),
        );

        let source_rules = reminders
            .iter()
            .map(|reminder| reminder.source_rule.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            source_rules,
            ["assoc-annual", "cooperativa-annual", "fundacao-annual"]
        );
        assert!(
            reminders
                .iter()
                .all(|reminder| reminder.due_date == "2026-03-31")
        );
    }

    #[test]
    fn profile_calendar_reminder_is_suppressed_by_recent_sealed_signal() {
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = Book::new(entity.id, BookKind::AssembleiaGeral);
        let mut act = Act::draft(book.id, "Ata da assembleia geral", MeetingChannel::Physical);
        act.meeting_date = Some(date!(2026 - 03 - 30));
        act.state = ActState::Sealed;

        let mut entities = HashMap::new();
        entities.insert(entity.id, entity);
        let mut books = HashMap::new();
        books.insert(book.id, book);
        let mut acts = HashMap::new();
        acts.insert(act.id, act);

        let reminders = dashboard_reminders(
            &entities,
            &books,
            &acts,
            &HashMap::new(),
            date!(2026 - 07 - 09),
        );

        assert!(reminders.is_empty());
    }

    #[test]
    fn profile_calendar_reminder_is_limited_to_reviewed_commercial_entities() {
        let entity = entity_of(EntityKind::SociedadeEmNomeColetivo);
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2026 - 07 - 09),
        );

        assert!(reminders.is_empty());
    }

    #[test]
    fn unsupported_profile_calendar_without_due_offset_emits_no_false_reminder() {
        let entity = entity_of(EntityKind::Condominio);
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2026 - 01 - 15),
        );

        assert!(
            reminders.is_empty(),
            "condominium profile has no encoded fiscal-year offset yet"
        );
    }

    #[test]
    fn stale_inconsistent_profile_data_emits_no_reminder() {
        let mut entity = entity_of(EntityKind::Associacao);
        entity.family = EntityFamily::CommercialCompany;
        assert!(!entity.is_consistent());
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2026 - 01 - 15),
        );

        assert!(reminders.is_empty());
    }

    #[test]
    fn leap_day_fiscal_year_end_is_clamped_deterministically() {
        let fiscal_year_end = FiscalYearEnd { month: 2, day: 29 };

        assert_eq!(
            format_date(annual_due_date_for_year(2024, fiscal_year_end, 3)),
            "2024-05-29"
        );
        assert_eq!(
            format_date(annual_due_date_for_year(2025, fiscal_year_end, 3)),
            "2025-05-28"
        );
    }

    #[test]
    fn duplicate_due_dates_are_ordered_deterministically() {
        let first_id = "00000000-0000-4000-8000-000000000001";
        let second_id = "00000000-0000-4000-8000-000000000002";
        let first = named_entity(EntityKind::Associacao, "Associacao Duplicada", first_id);
        let second = named_entity(EntityKind::Associacao, "Associacao Duplicada", second_id);
        let mut entities = HashMap::new();
        entities.insert(second.id, second);
        entities.insert(first.id, first);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2026 - 01 - 15),
        );

        assert_eq!(reminders.len(), 2);
        assert_eq!(reminders[0].entity_id, first_id);
        assert_eq!(reminders[1].entity_id, second_id);
        assert_eq!(reminders[0].due_date, reminders[1].due_date);
        assert_eq!(reminders[0].entity_name, reminders[1].entity_name);
    }
}
