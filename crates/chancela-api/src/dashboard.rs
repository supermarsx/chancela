//! Dashboard endpoint (contract §2.7): the WFL-40 counts plus the recent-events feed.

use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use chancela_core::{
    Act, ActId, ActState, Book, BookId, BookKind, BookState, CalendarPreset, Entity, EntityFamily,
    EntityId, EntityKind, ProfileCalendarDueRule, ProfileCalendarEvaluationContext,
    ProfileCalendarNoClaimFlags, ProfileCalendarPlan, ProfileCalendarRuleEvaluation,
    ProfileCalendarScheduledRule, ProfileCalendarUnsupportedRule, Severity,
    evaluate_profile_calendar_rule, profile_calendar_plan_for, profile_for, rule_pack_for,
    supports_profile_calendar_plan,
};
use chancela_law::{LawCatalog, Verification};
use chancela_registry::RegistryExtract;
use chancela_store::{
    StoredDocument, StoredFollowUp, StoredFollowUpStatus, StoredGeneratedDocumentDispatchEvidence,
    StoredImportedDocumentMeta, StoredImportedDocumentReviewStatus,
};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::authorizer;
use crate::backup_recovery::{
    BackupRecoveryFreshnessReview, BackupRecoveryFreshnessStatus, backup_recovery_freshness_review,
    sort_backup_recovery_drill_receipts,
};
use crate::dto::{
    DashboardActStateCounts, DashboardAction, DashboardAlert, DashboardAlertTarget,
    DashboardCurrentWork, DashboardI18n, DashboardLawReference, DashboardOpenBook,
    DashboardProfileCalendarDueRule, DashboardProfileCalendarEvaluation,
    DashboardProfileCalendarNoClaimFlags, DashboardProfileCalendarPlan, DashboardReminder,
    DashboardResponse, DashboardTargetLinks, LedgerEventView, compute_expired, format_date,
    read_redaction_for_actor,
};
use crate::error::ApiError;
use crate::privacy::{
    BreachPlaybookId, BreachPlaybookRecord, PrivacyAdvisoryReviewStatus, PrivacyRecordStatus,
    TransferControlId, TransferControlRecord, breach_playbook_advisory_review,
    transfer_control_advisory_review,
};
use crate::settings::WorkflowReminderSettings;

const REGISTRY_EXPIRY_WARNING_DAYS: i32 = 30;

#[derive(Clone)]
struct GeneratedDispatchEvidenceSnapshot {
    document: StoredDocument,
    evidence: Vec<StoredGeneratedDocumentDispatchEvidence>,
}

/// `GET /v1/dashboard` — aggregate counts and the last ten ledger events.
pub async fn dashboard(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<DashboardResponse>, ApiError> {
    // RBAC (t64-E3): the dashboard aggregates act data → `act.read` at Global.
    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::ActRead, Scope::Global)?;
    let can_view_backup_recovery_freshness = authz
        .permits(Permission::LedgerRecover, Scope::Global)
        || authz.permits(Permission::DataBackup, Scope::Global);
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let settings = state.settings.read().await;
    let reminder_policy = settings.workflow.reminders.clone();
    let backup_recovery_policy = settings.data_management.backup_recovery.clone();
    drop(settings);
    let now = OffsetDateTime::now_utc();
    let backup_recovery_alert = if can_view_backup_recovery_freshness {
        let mut receipts = state.backup_recovery_drill_receipts.read().await.clone();
        sort_backup_recovery_drill_receipts(&mut receipts);
        let freshness = backup_recovery_freshness_review(&receipts, backup_recovery_policy, now);
        backup_recovery_freshness_alert(&freshness)
    } else {
        None
    };
    // entities → books → acts → follow_ups → registry_extracts → ledger (read locks; the global order).
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;
    let follow_ups = state.follow_ups.read().await;
    let registry_extracts = state.registry_extracts.read().await;
    let breach_playbooks = state.breach_playbooks.read().await;
    let transfer_controls = state.transfer_controls.read().await;
    let generated_dispatch_evidence =
        load_generated_dispatch_evidence_snapshots(&state, &acts).await?;
    let imported_documents = load_imported_document_metadata(&state).await?;
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

    // wp14 Phase 4: serve the O(n) chain-verify verdict from the in-process memo (keyed by the
    // ledger head + length), so this hot path is O(1) over an unchanged chain. Transparent memo of
    // `ledger.verify()`; identical semantics.
    let (ledger_valid, ledger_length) = match state.verify_cache.verdict(&ledger) {
        Ok(len) => (true, len),
        Err(_) => (false, ledger.len() as u64),
    };

    // Last ten events in append order.
    let events = ledger.events();
    let start = events.len().saturating_sub(10);
    let recent_events = if redaction.is_guest() {
        Vec::new()
    } else {
        events[start..].iter().map(LedgerEventView::from).collect()
    };
    let today = now.date();
    let current_work = dashboard_current_work(&entities, &books, &acts);
    let mut alerts = dashboard_alerts(
        &entities,
        &books,
        &acts,
        &registry_extracts,
        ledger_valid,
        today,
    );
    if let Some(alert) = backup_recovery_alert {
        alerts.push(alert);
        sort_dashboard_alerts(&mut alerts);
    }
    let reminders = dashboard_reminders_with_generated_dispatch_evidence(
        ReminderInputs {
            entities: &entities,
            books: &books,
            acts: &acts,
            follow_ups: &follow_ups,
            generated_dispatch_evidence: &generated_dispatch_evidence,
            imported_documents: &imported_documents,
            registry_extracts: &registry_extracts,
            breach_playbooks: &breach_playbooks,
            transfer_controls: &transfer_controls,
        },
        today,
        &reminder_policy,
    );

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

async fn load_generated_dispatch_evidence_snapshots(
    state: &AppState,
    acts: &HashMap<ActId, Act>,
) -> Result<Vec<GeneratedDispatchEvidenceSnapshot>, ApiError> {
    if let Some(store) = &state.store {
        let mut snapshots = Vec::new();
        for act in acts
            .values()
            .filter(|act| act.state == ActState::Sealed && act.ata_number.is_some())
        {
            let docs = store
                .documents_for_act(act.id)
                .map_err(|e| ApiError::Internal(format!("document store read failed: {e}")))?;
            for document in docs.into_iter().filter(|document| {
                document.template_id
                    == crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID
            }) {
                let evidence = store
                    .generated_document_dispatch_evidence(&document.id)
                    .map_err(|e| {
                        ApiError::Internal(format!("dispatch evidence store read failed: {e}"))
                    })?;
                snapshots.push(GeneratedDispatchEvidenceSnapshot { document, evidence });
            }
        }
        return Ok(snapshots);
    }

    let documents = state
        .documents
        .read()
        .await
        .values()
        .filter(|document| {
            document.template_id
                == crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID
                && acts.contains_key(&document.act_id)
        })
        .cloned()
        .collect::<Vec<_>>();

    Ok(documents
        .into_iter()
        .map(|document| GeneratedDispatchEvidenceSnapshot {
            document,
            evidence: Vec::new(),
        })
        .collect())
}

async fn load_imported_document_metadata(
    state: &AppState,
) -> Result<Vec<StoredImportedDocumentMeta>, ApiError> {
    if let Some(store) = &state.store {
        return store
            .imported_documents(None)
            .map_err(|e| ApiError::Internal(format!("imported document store read failed: {e}")));
    }
    Ok(Vec::new())
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

    sort_dashboard_alerts(&mut alerts);
    alerts
}

fn sort_dashboard_alerts(alerts: &mut [DashboardAlert]) {
    alerts.sort_by(|a, b| {
        a.label
            .cmp(&b.label)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.target.entity_id.cmp(&b.target.entity_id))
            .then_with(|| a.target.book_id.cmp(&b.target.book_id))
            .then_with(|| a.target.act_id.cmp(&b.target.act_id))
    });
}

fn backup_recovery_freshness_alert(
    freshness: &BackupRecoveryFreshnessReview,
) -> Option<DashboardAlert> {
    let status = backup_recovery_freshness_status_value(&freshness.status);
    if matches!(freshness.status, BackupRecoveryFreshnessStatus::Fresh) {
        return None;
    }

    let latest_receipt_at = freshness
        .latest_receipt_at
        .clone()
        .unwrap_or_else(|| "not_recorded".to_owned());
    let latest_receipt_age_days = freshness
        .latest_receipt_age_days
        .map(|days| days.to_string())
        .unwrap_or_else(|| "not_recorded".to_owned());
    let latest_receipt_preflight_ready =
        optional_bool_param(freshness.latest_receipt_preflight_ready);
    let latest_receipt_isolated_restore_verified =
        optional_bool_param(freshness.latest_receipt_isolated_restore_verified);

    Some(DashboardAlert {
        code: "backup.recovery.freshness_advisory".to_owned(),
        label: "Advisory".to_owned(),
        severity: "Warning".to_owned(),
        category: "BackupRecoveryFreshness".to_owned(),
        message: format!(
            "Local backup recovery drill freshness is {status}; policy max age is {} days, latest receipt date is {latest_receipt_at}, latest receipt age is {latest_receipt_age_days} days, preflight readiness is {latest_receipt_preflight_ready}, and isolated snapshot verification is {latest_receipt_isolated_restore_verified}. This is a local advisory from stored recovery-drill receipts only; it does not run recovery, inspect archives, restore data, or certify production readiness.",
            freshness.policy.max_drill_age_days
        ),
        params: dashboard_alert_params([
            ("freshness_status", status.to_owned()),
            (
                "policy_max_drill_age_days",
                freshness.policy.max_drill_age_days.to_string(),
            ),
            ("latest_receipt_at", latest_receipt_at),
            ("latest_receipt_age_days", latest_receipt_age_days),
            (
                "latest_receipt_preflight_ready",
                latest_receipt_preflight_ready,
            ),
            (
                "latest_receipt_isolated_restore_verified",
                latest_receipt_isolated_restore_verified,
            ),
        ]),
        target: DashboardAlertTarget {
            entity_id: None,
            book_id: None,
            act_id: None,
            links: DashboardTargetLinks {
                entity: None,
                book: None,
                act: None,
                ledger: None,
            },
        },
        source: Some("backup_recovery.freshness".to_owned()),
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_backup_recovery_policy",
            "notifications.alert.backupRecoveryFreshness.action",
            None,
            Some("/configuracoes?sec=dados".to_owned()),
        )),
        recommended_next_steps: vec![
            "Review the local recovery-drill receipt freshness state in Data Management."
                .to_owned(),
            "Record a new non-destructive recovery drill only when operator evidence exists."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.alert.backupRecoveryFreshness.title",
            "notifications.alert.backupRecoveryFreshness.body",
            Some("notifications.alert.backupRecoveryFreshness.action"),
        )),
    })
}

fn backup_recovery_freshness_status_value(status: &BackupRecoveryFreshnessStatus) -> &'static str {
    match status {
        BackupRecoveryFreshnessStatus::NoReceipt => "no_receipt",
        BackupRecoveryFreshnessStatus::Fresh => "fresh",
        BackupRecoveryFreshnessStatus::Stale => "stale",
        BackupRecoveryFreshnessStatus::Failed => "failed",
    }
}

fn optional_bool_param(value: Option<bool>) -> String {
    value.unwrap_or(false).to_string()
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
            let remuneration = remuneration_alert_profile(entity.kind);
            alerts.push(DashboardAlert {
                code: remuneration.code.to_owned(),
                label: "Advisory".to_owned(),
                severity: "Info".to_owned(),
                category: "GovernanceSetup".to_owned(),
                message: format!(
                    "Entity {} has {} officers in the imported registry evidence, but no sealed remuneration or non-remuneration minutes are recorded. Record the remuneration setup when appropriate.",
                    entity.name, remuneration.officer_label
                ),
                params: dashboard_alert_params([
                    ("entity_id", entity.id.to_string()),
                    ("entity_name", entity.name.clone()),
                    ("office", remuneration.officer_label.to_owned()),
                    ("recommended_actions", "record_remuneration,record_non_remuneration".to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(entity.id.to_string()),
                    book_id: None,
                    act_id: None,
                    links: target_links(Some(entity.id), None, None),
                },
                source: Some("registry_extracts.orgaos".to_owned()),
                law_refs: law_refs(&[("csc", remuneration.article)]),
                action: Some(dashboard_action(
                    "open_entity",
                    remuneration.action_key,
                    Some(format!("/v1/entities/{}", entity.id)),
                    Some(format!("/entidades/{}", entity.id)),
                )),
                recommended_next_steps: vec![
                    "Review the registry officers and statutes.".to_owned(),
                    "Draft minutes for remuneration or explicit non-remuneration if required.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    remuneration.title_key,
                    remuneration.body_key,
                    Some(remuneration.action_key),
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

    for book in books.values().filter(|book| book.legal_hold.is_some()) {
        let hold = book.legal_hold.as_ref().expect("filtered legal hold");
        alerts.push(DashboardAlert {
            code: "book.legal_hold.active".to_owned(),
            label: "ReviewRequired".to_owned(),
            severity: "Warning".to_owned(),
            category: "ArchiveRetention".to_owned(),
            message: format!(
                "Book {} has an active legal hold set by {}. Review the hold before archive disposal decisions.",
                book.id, hold.actor
            ),
            params: dashboard_alert_params([
                ("book_id", book.id.to_string()),
                ("entity_id", book.entity_id.to_string()),
                ("book_kind", format!("{:?}", book.kind)),
                ("legal_hold_reason", hold.reason.clone()),
                ("legal_hold_actor", hold.actor.clone()),
                ("legal_hold_set_at", rfc3339(hold.set_at)),
                (
                    "recommended_actions",
                    "review_legal_hold,review_archive_disposal".to_owned(),
                ),
            ]),
            target: DashboardAlertTarget {
                entity_id: Some(book.entity_id.to_string()),
                book_id: Some(book.id.to_string()),
                act_id: None,
                links: target_links(Some(book.entity_id), Some(book.id), None),
            },
            source: Some("books.legal_hold".to_owned()),
            law_refs: Vec::new(),
            action: Some(dashboard_action(
                "open_book_legal_hold",
                "notifications.alert.book.legalHold.action",
                Some(format!("/v1/books/{}/legal-hold", book.id)),
                Some(format!("/livros/{}", book.id)),
            )),
            recommended_next_steps: vec![
                "Open the book legal-hold panel.".to_owned(),
                "Review the hold reason before any archive disposal decision.".to_owned(),
            ],
            i18n: Some(alert_i18n(
                "notifications.alert.book.legalHold.title",
                "notifications.alert.book.legalHold.body",
                Some("notifications.alert.book.legalHold.action"),
            )),
        });
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

    for act in acts
        .values()
        .filter(|act| matches!(act.state, ActState::Sealed))
    {
        let Some(book) = books.get(&act.book_id) else {
            continue;
        };
        let entity_id = book.entity_id;
        alerts.push(DashboardAlert {
            code: "act.archive.pending".to_owned(),
            label: "Advisory".to_owned(),
            severity: "Info".to_owned(),
            category: "ArchiveStatus".to_owned(),
            message: format!(
                "Act {} is sealed but not archived. Archive it when the preservation evidence is ready.",
                act.id
            ),
            params: dashboard_alert_params([
                ("act_id", act.id.to_string()),
                ("book_id", book.id.to_string()),
                ("entity_id", entity_id.to_string()),
                ("act_title", act.title.clone()),
                ("current_state", format!("{:?}", act.state)),
                ("recommended_actions", "archive_act".to_owned()),
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
                "archive_act",
                "notifications.alert.act.archivePending.action",
                Some(format!("/v1/acts/{}/archive", act.id)),
                Some(format!("/atas/{}", act.id)),
            )),
            recommended_next_steps: vec![
                "Open the sealed act.".to_owned(),
                "Archive it when the preservation evidence is ready.".to_owned(),
            ],
            i18n: Some(alert_i18n(
                "notifications.alert.act.archivePending.title",
                "notifications.alert.act.archivePending.body",
                Some("notifications.alert.act.archivePending.action"),
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

/// The corpus authenticity tier as its stable wire string, matching the [`Verification`] serde
/// value: `"Verified"` (human-approved) / `"automated_review"` (vendored + auto-reviewed, NOT
/// human-approved) / `"Pending"` (no text). Kept in lockstep with the enum's serde so the dashboard
/// contract and the `/v1/law` corpus surface agree on the badge value.
fn law_verification_wire(v: Verification) -> &'static str {
    match v {
        Verification::Verified => "Verified",
        Verification::AutomatedReview => "automated_review",
        Verification::Pending => "Pending",
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
                    verification: law_verification_wire(article.verification).to_owned(),
                    source_url: article.source.url.clone(),
                    source_complete: article.source.is_complete(),
                    // Only automated-review articles carry these; verified/pending leave them null.
                    review_method: article.source.review_method.clone(),
                    review_note: article.source.review_note.clone(),
                })
                .unwrap_or_else(|| DashboardLawReference {
                    diploma_id: (*diploma_id).to_owned(),
                    article: (*article_number).to_owned(),
                    label: format!("Artigo {article_number}"),
                    heading: String::new(),
                    verification: "Missing".to_owned(),
                    source_url: None,
                    source_complete: false,
                    review_method: None,
                    review_note: None,
                })
        })
        .collect()
}

struct RemunerationAlertProfile {
    code: &'static str,
    officer_label: &'static str,
    article: &'static str,
    title_key: &'static str,
    body_key: &'static str,
    action_key: &'static str,
}

fn remuneration_alert_profile(kind: EntityKind) -> RemunerationAlertProfile {
    if matches!(kind, EntityKind::SociedadeAnonima) {
        RemunerationAlertProfile {
            code: "entity.administrator_remuneration.setup_recommended",
            officer_label: "administration",
            article: "399",
            title_key: "notifications.alert.entity.administratorRemuneration.title",
            body_key: "notifications.alert.entity.administratorRemuneration.body",
            action_key: "notifications.alert.entity.administratorRemuneration.action",
        }
    } else {
        RemunerationAlertProfile {
            code: "entity.manager_remuneration.setup_recommended",
            officer_label: "management",
            article: "255",
            title_key: "notifications.alert.entity.managerRemuneration.title",
            body_key: "notifications.alert.entity.managerRemuneration.body",
            action_key: "notifications.alert.entity.managerRemuneration.action",
        }
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

fn is_sa_or_lda_like(kind: EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::SociedadeAnonima
            | EntityKind::SociedadePorQuotas
            | EntityKind::SociedadeUnipessoalPorQuotas
    )
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

fn dashboard_reminder_due_date_sort_key(reminder: &DashboardReminder) -> (bool, Option<Date>) {
    let due_date = parse_dashboard_date(reminder.due_date.trim());
    (due_date.is_none(), due_date)
}

fn rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
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

#[cfg(test)]
fn dashboard_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    registry_extracts: &HashMap<EntityId, RegistryExtract>,
    today: Date,
) -> Vec<DashboardReminder> {
    dashboard_reminders_with_follow_ups(
        entities,
        books,
        acts,
        &HashMap::new(),
        registry_extracts,
        today,
        &WorkflowReminderSettings::default(),
    )
}

#[cfg(test)]
fn dashboard_reminders_with_follow_ups(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    follow_ups: &HashMap<String, StoredFollowUp>,
    registry_extracts: &HashMap<EntityId, RegistryExtract>,
    today: Date,
    policy: &WorkflowReminderSettings,
) -> Vec<DashboardReminder> {
    dashboard_reminders_with_generated_dispatch_evidence(
        ReminderInputs {
            entities,
            books,
            acts,
            follow_ups,
            generated_dispatch_evidence: &[],
            imported_documents: &[],
            registry_extracts,
            breach_playbooks: &HashMap::new(),
            transfer_controls: &HashMap::new(),
        },
        today,
        policy,
    )
}

/// Borrowed snapshot of the store collections a reminder pass reads. Bundled so the reminder
/// entry point stays a small `(inputs, today, policy)` signature instead of a long positional list.
struct ReminderInputs<'a> {
    entities: &'a HashMap<EntityId, Entity>,
    books: &'a HashMap<BookId, Book>,
    acts: &'a HashMap<ActId, Act>,
    follow_ups: &'a HashMap<String, StoredFollowUp>,
    generated_dispatch_evidence: &'a [GeneratedDispatchEvidenceSnapshot],
    imported_documents: &'a [StoredImportedDocumentMeta],
    registry_extracts: &'a HashMap<EntityId, RegistryExtract>,
    breach_playbooks: &'a HashMap<BreachPlaybookId, BreachPlaybookRecord>,
    transfer_controls: &'a HashMap<TransferControlId, TransferControlRecord>,
}

fn dashboard_reminders_with_generated_dispatch_evidence(
    inputs: ReminderInputs<'_>,
    today: Date,
    policy: &WorkflowReminderSettings,
) -> Vec<DashboardReminder> {
    let ReminderInputs {
        entities,
        books,
        acts,
        follow_ups,
        generated_dispatch_evidence,
        imported_documents,
        registry_extracts,
        breach_playbooks,
        transfer_controls,
    } = inputs;
    if !policy.enabled {
        return Vec::new();
    }

    let mut reminders = Vec::new();
    if policy.sources.act_follow_ups {
        reminders.extend(follow_up_reminders(
            entities,
            books,
            acts,
            follow_ups,
            today,
            policy.due_soon_days,
        ));
    }
    if policy.sources.attendance_hygiene {
        reminders.extend(open_act_attendance_reminders(
            entities,
            books,
            acts,
            today,
            policy.attendance_lookahead_days,
            policy.due_soon_days,
        ));
    }
    reminders.extend(open_act_convocation_notice_reminders(
        entities,
        books,
        acts,
        today,
        policy.due_soon_days,
    ));
    reminders.extend(absent_owner_dispatch_evidence_reminders(
        entities,
        books,
        acts,
        generated_dispatch_evidence,
    ));
    reminders.extend(imported_document_review_reminders(
        entities,
        books,
        acts,
        imported_documents,
    ));
    if policy.sources.privacy_control_reviews {
        reminders.extend(privacy_control_review_reminders(
            breach_playbooks,
            transfer_controls,
            today,
            policy.due_soon_days,
        ));
    }
    if policy.sources.profile_calendar {
        reminders.extend(
            entities
                .values()
                .flat_map(|entity| {
                    let context = ProfileCalendarReminderContext {
                        books,
                        acts,
                        registry_extract: registry_extracts.get(&entity.id),
                        today,
                        due_soon_days: policy.due_soon_days,
                    };
                    annual_general_meeting_reminders(entity, &context)
                })
                .collect::<Vec<_>>(),
        );
    }

    reminders.sort_by(|a, b| {
        dashboard_reminder_due_date_sort_key(a)
            .cmp(&dashboard_reminder_due_date_sort_key(b))
            .then_with(|| a.entity_name.cmp(&b.entity_name))
            .then_with(|| a.entity_id.cmp(&b.entity_id))
            .then_with(|| a.source_profile.cmp(&b.source_profile))
            .then_with(|| a.source_rule.cmp(&b.source_rule))
    });
    reminders.truncate(policy.dashboard_limit as usize);
    reminders
}

fn follow_up_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    follow_ups: &HashMap<String, StoredFollowUp>,
    today: Date,
    due_soon_days: u16,
) -> Vec<DashboardReminder> {
    follow_ups
        .values()
        .filter(|follow_up| follow_up.status == StoredFollowUpStatus::Open)
        .filter_map(|follow_up| {
            let due_date = follow_up.due_date?;
            let act = acts.get(&follow_up.act_id)?;
            let book = books.get(&act.book_id)?;
            let entity = entities.get(&book.entity_id)?;
            Some(follow_up_reminder(
                entity,
                book,
                act,
                follow_up,
                due_date,
                today,
                due_soon_days,
            ))
        })
        .collect()
}

fn open_act_attendance_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    today: Date,
    attendance_lookahead_days: u16,
    due_soon_days: u16,
) -> Vec<DashboardReminder> {
    acts.values()
        .filter_map(|act| {
            let book = books.get(&act.book_id)?;
            if book.state != BookState::Open || !is_pre_signing_work_queue_state(act.state) {
                return None;
            }
            let entity = entities.get(&book.entity_id)?;
            if !entity.is_consistent() {
                return None;
            }
            act_attendance_reminder(
                entity,
                book,
                act,
                today,
                attendance_lookahead_days,
                due_soon_days,
            )
        })
        .collect()
}

fn act_attendance_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    today: Date,
    attendance_lookahead_days: u16,
    due_soon_days: u16,
) -> Option<DashboardReminder> {
    let due_date = act.meeting_date?;
    let days_until = due_date.to_julian_day() - today.to_julian_day();
    if days_until > i32::from(attendance_lookahead_days) {
        return None;
    }

    let missing_fields = missing_attendance_fields(act);
    if missing_fields.is_empty() {
        return None;
    }

    let due_date_text = format_date(due_date);
    let status = reminder_status(today, due_date, due_soon_days).to_owned();
    let severity = if status == "Overdue" {
        "Warning"
    } else {
        "Info"
    }
    .to_owned();
    let missing_fields_text = missing_fields.join(",");
    let profile = profile_for(entity.kind);

    Some(DashboardReminder {
        due_date: due_date_text.clone(),
        severity,
        status,
        reason: format!(
            "Act \"{}\" is dated for {} but is missing attendance capture ({}). \
             Record the attendance reference and either presence counts or structured attendees before advancing it.",
            act.title, due_date_text, missing_fields_text
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "act-attendance-missing".to_owned(),
        source_profile: profile.template_family.to_owned(),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("meeting_date", due_date_text),
            ("act_state", format!("{:?}", act.state)),
            ("missing_fields", missing_fields_text),
            (
                "days_until",
                (due_date.to_julian_day() - today.to_julian_day()).to_string(),
            ),
        ]),
        profile_calendar_plan: None,
        law_refs: act_attendance_law_refs(entity.family),
        action: Some(dashboard_action(
            "open_act_attendance",
            "notifications.reminder.act.attendance.action",
            Some(format!("/v1/acts/{}", act.id)),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the act.".to_owned(),
            "Record the attendance reference and presence counts or structured attendee rows."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.act.attendance.title",
            "notifications.reminder.act.attendance.body",
            Some("notifications.reminder.act.attendance.action"),
        )),
    })
}

fn is_pre_signing_work_queue_state(state: ActState) -> bool {
    matches!(
        state,
        ActState::Draft
            | ActState::Review
            | ActState::Convened
            | ActState::Deliberated
            | ActState::TextApproved
    )
}

fn missing_attendance_fields(act: &Act) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if act
        .attendance_reference
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        missing.push("attendance_reference");
    }
    if act.members_present.is_none()
        && act.members_represented.is_none()
        && act.attendees.is_empty()
    {
        missing.push("presence_counts_or_attendees");
    }
    missing
}

fn act_attendance_law_refs(family: EntityFamily) -> Vec<DashboardLawReference> {
    match family {
        EntityFamily::CommercialCompany => law_refs(&[("csc", "63")]),
        _ => Vec::new(),
    }
}

fn open_act_convocation_notice_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    today: Date,
    due_soon_days: u16,
) -> Vec<DashboardReminder> {
    acts.values()
        .filter_map(|act| {
            let book = books.get(&act.book_id)?;
            if book.state != BookState::Open || !is_pre_signing_work_queue_state(act.state) {
                return None;
            }
            let entity = entities.get(&book.entity_id)?;
            if !entity.is_consistent() {
                return None;
            }
            act_convocation_notice_reminder(entity, book, act, today, due_soon_days)
        })
        .collect()
}

fn act_convocation_notice_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    today: Date,
    due_soon_days: u16,
) -> Option<DashboardReminder> {
    let required_days = entity.statute.as_ref()?.convocation_notice_days?;
    let dispatch_date = act
        .convening
        .as_ref()
        .and_then(|convening| convening.dispatch_date);
    let antecedence_days = act_convocation_notice_antecedence_days(act);
    let Some(meeting_date) = act.meeting_date else {
        return Some(act_convocation_notice_missing_meeting_date_reminder(
            entity,
            book,
            act,
            required_days,
            dispatch_date,
            antecedence_days,
        ));
    };
    let notice_due_date =
        Date::from_julian_day(meeting_date.to_julian_day() - i32::from(required_days)).ok()?;

    if antecedence_days
        .map(|actual| actual >= i32::from(required_days))
        .unwrap_or(false)
    {
        return None;
    }

    let meeting_date_text = format_date(meeting_date);
    let notice_due_date_text = format_date(notice_due_date);
    let dispatch_date_text = dispatch_date.map(format_date).unwrap_or_default();
    let antecedence_days_text = antecedence_days
        .map(|days| days.to_string())
        .unwrap_or_default();
    let evidence_status = if antecedence_days.is_some() {
        "short_dispatch_evidence"
    } else {
        "missing_or_unverifiable_dispatch_evidence"
    };
    let profile = profile_for(entity.kind);

    Some(DashboardReminder {
        due_date: notice_due_date_text.clone(),
        severity: "Warning".to_owned(),
        status: reminder_status(today, notice_due_date, due_soon_days).to_owned(),
        reason: format!(
            "Act \"{}\" has a local statute convocation-notice advisory of {} days for meeting date {}. \
             Recorded convening dispatch evidence is {} and does not demonstrate the configured notice period. \
             This is a local advisory over recorded statute/convening metadata only; no legal sufficiency, \
             external delivery, or workflow completion is claimed.",
            act.title, required_days, meeting_date_text, evidence_status
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "act-convening-notice".to_owned(),
        source_profile: profile.template_family.to_owned(),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("required_notice_days", required_days.to_string()),
            ("meeting_date", meeting_date_text),
            ("notice_due_date", notice_due_date_text),
            ("dispatch_date", dispatch_date_text),
            ("antecedence_days", antecedence_days_text),
            ("evidence_status", evidence_status.to_owned()),
            ("act_state", format!("{:?}", act.state)),
            ("local_advisory_only", "true".to_owned()),
            ("legal_sufficiency_claimed", "false".to_owned()),
            ("external_delivery_claimed", "false".to_owned()),
            ("workflow_completion_claimed", "false".to_owned()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_act_convening_notice",
            "notifications.reminder.act.conveningNotice.action",
            Some(format!("/v1/acts/{}", act.id)),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the act.".to_owned(),
            "Review the recorded convening dispatch date and actual antecedence metadata."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.act.conveningNotice.title",
            "notifications.reminder.act.conveningNotice.body",
            Some("notifications.reminder.act.conveningNotice.action"),
        )),
    })
}

fn act_convocation_notice_missing_meeting_date_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    required_days: u16,
    dispatch_date: Option<Date>,
    antecedence_days: Option<i32>,
) -> DashboardReminder {
    let dispatch_date_text = dispatch_date.map(format_date).unwrap_or_default();
    let antecedence_days_text = antecedence_days
        .map(|days| days.to_string())
        .unwrap_or_default();
    let profile = profile_for(entity.kind);

    DashboardReminder {
        due_date: String::new(),
        severity: "Warning".to_owned(),
        status: "Pending".to_owned(),
        reason: format!(
            "Act \"{}\" has a local configured convocation-notice advisory of {} days, but no \
             meeting date is recorded. The local notice due date cannot be computed until the \
             meeting date is recorded. Review the act metadata and recorded convening dispatch \
             evidence before advancing it. This is a local advisory over recorded \
             statute/convening metadata only; no legal sufficiency is claimed, and no legal \
             deadline computation, external delivery, workflow completion, registry/DRE \
             acceptance, or provider acceptance is claimed.",
            act.title, required_days
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "act-convening-notice".to_owned(),
        source_profile: profile.template_family.to_owned(),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("required_notice_days", required_days.to_string()),
            ("meeting_date", String::new()),
            ("notice_due_date", String::new()),
            ("dispatch_date", dispatch_date_text),
            ("antecedence_days", antecedence_days_text),
            ("evidence_status", "missing_meeting_date".to_owned()),
            ("notice_due_date_computable", "false".to_owned()),
            (
                "notice_due_date_blocked_by",
                "missing_meeting_date".to_owned(),
            ),
            ("local_deadline_computed", "false".to_owned()),
            ("local_advisory_only", "true".to_owned()),
            ("legal_sufficiency_claimed", "false".to_owned()),
            ("legal_deadline_computation_claimed", "false".to_owned()),
            ("external_delivery_claimed", "false".to_owned()),
            ("workflow_completion_claimed", "false".to_owned()),
            ("registry_acceptance_claimed", "false".to_owned()),
            ("dre_acceptance_claimed", "false".to_owned()),
            ("provider_acceptance_claimed", "false".to_owned()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_act_convening_notice",
            "notifications.reminder.act.conveningNotice.action",
            Some(format!("/v1/acts/{}", act.id)),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the act.".to_owned(),
            "Record the meeting date before computing the local notice due date.".to_owned(),
            "Review the recorded convening dispatch evidence after the meeting date is known."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.act.conveningNotice.title",
            "notifications.reminder.act.conveningNotice.missingMeetingDate.body",
            Some("notifications.reminder.act.conveningNotice.action"),
        )),
    }
}

fn act_convocation_notice_antecedence_days(act: &Act) -> Option<i32> {
    let convening = act.convening.as_ref()?;
    if let Some(days) = convening.antecedence_days {
        return Some(i32::from(days));
    }

    let dispatch_date = convening.dispatch_date?;
    let meeting_date = act.meeting_date?;
    Some(meeting_date.to_julian_day() - dispatch_date.to_julian_day())
}

fn imported_document_review_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    imported_documents: &[StoredImportedDocumentMeta],
) -> Vec<DashboardReminder> {
    imported_documents
        .iter()
        .filter(|document| {
            imported_document_status_requires_review(document.operator_review_status)
        })
        .filter_map(|document| {
            let act_id = document.act_id?;
            let act = acts.get(&act_id)?;
            let book = books.get(&act.book_id)?;
            let entity = entities.get(&book.entity_id)?;
            Some(imported_document_review_reminder(
                entity, book, act, document,
            ))
        })
        .collect()
}

fn imported_document_status_requires_review(status: StoredImportedDocumentReviewStatus) -> bool {
    matches!(
        status,
        StoredImportedDocumentReviewStatus::OperatorReviewRequired
            | StoredImportedDocumentReviewStatus::OcrReviewRequired
            | StoredImportedDocumentReviewStatus::CanonicalConversionReviewRequired
    )
}

fn imported_document_review_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    document: &StoredImportedDocumentMeta,
) -> DashboardReminder {
    let review_status = document.operator_review_status.as_str().to_owned();
    DashboardReminder {
        due_date: String::new(),
        severity: "Advisory".to_owned(),
        status: "Pending".to_owned(),
        reason: format!(
            "Imported document {} for act \"{}\" still requires operator review ({review_status}).",
            document.id, act.title
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "imported-document-review-required".to_owned(),
        source_profile: format!("imported-document-review:{}", document.id),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("imported_document_id", document.id.clone()),
            ("operator_review_status", review_status.clone()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_imported_document_review",
            "notifications.reminder.importedDocumentReview.action",
            Some(format!("/v1/documents/imported/{}", document.id)),
            Some(format!(
                "/atas/{}?imported_document_id={}&focus=import-review#imported-documents",
                act.id, document.id
            )),
        )),
        recommended_next_steps: vec![
            "Open the act imported-document panel.".to_owned(),
            "Use the existing imported-document review form to record an operator workflow decision."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.importedDocumentReview.title",
            "notifications.reminder.importedDocumentReview.body",
            Some("notifications.reminder.importedDocumentReview.action"),
        )),
    }
}

fn absent_owner_dispatch_evidence_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    generated_dispatch_evidence: &[GeneratedDispatchEvidenceSnapshot],
) -> Vec<DashboardReminder> {
    generated_dispatch_evidence
        .iter()
        .filter_map(|snapshot| {
            absent_owner_dispatch_evidence_reminder(entities, books, acts, snapshot)
        })
        .collect()
}

fn absent_owner_dispatch_evidence_reminder(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    snapshot: &GeneratedDispatchEvidenceSnapshot,
) -> Option<DashboardReminder> {
    let document = &snapshot.document;
    if document.template_id != crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID
    {
        return None;
    }
    let act = acts.get(&document.act_id)?;
    if act.state != ActState::Sealed || act.ata_number.is_none() {
        return None;
    }
    let book = books.get(&act.book_id)?;
    let entity = entities.get(&book.entity_id)?;
    if entity.family != EntityFamily::Condominium {
        return None;
    }

    let required_recipients = crate::documents::absent_owner_recipient_names(act);
    if required_recipients.is_empty() {
        return None;
    }
    let recorded_recipients = snapshot
        .evidence
        .iter()
        .filter(|row| {
            row.document_id == document.id
                && row.act_id == document.act_id
                && row.template_id == document.template_id
        })
        .flat_map(|row| row.recipients.iter().cloned())
        .collect::<Vec<_>>();
    let dispatch_status = crate::documents::dispatch_evidence_status_for_template(
        &document.template_id,
        &required_recipients,
        &recorded_recipients,
    )?;
    if !matches!(
        dispatch_status.status.as_str(),
        "required_pending" | "operator_evidence_partial"
    ) {
        return None;
    }

    Some(absent_owner_dispatch_evidence_dashboard_reminder(
        entity,
        book,
        act,
        document,
        &dispatch_status,
        snapshot.evidence.len(),
    ))
}

fn absent_owner_dispatch_evidence_dashboard_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    document: &StoredDocument,
    dispatch_status: &crate::documents::DispatchEvidenceStatusView,
    evidence_row_count: usize,
) -> DashboardReminder {
    let required_count = dispatch_status.required_recipients.len();
    let recorded_count = dispatch_status.recorded_recipients.len();
    let missing_count = dispatch_status.missing_recipients.len();
    let missing_recipients = dispatch_status.missing_recipients.join(", ");

    DashboardReminder {
        due_date: String::new(),
        severity: "Advisory".to_owned(),
        status: "Pending".to_owned(),
        reason: format!(
            "Generated absent-owner communication document {} for act \"{}\" has dispatch \
             evidence status {}. This dashboard reminder is advisory only and does not claim \
             sending, delivery, legal notice completion, or legal sufficiency.",
            document.id, act.title, dispatch_status.status
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "absent-owner-dispatch-evidence".to_owned(),
        source_profile: "condominium-generated-communication".to_owned(),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("document_id", document.id.clone()),
            ("template_id", document.template_id.clone()),
            ("dispatch_evidence_status", dispatch_status.status.clone()),
            ("required_recipient_count", required_count.to_string()),
            ("recorded_recipient_count", recorded_count.to_string()),
            ("missing_recipient_count", missing_count.to_string()),
            (
                "required_recipients",
                dispatch_status.required_recipients.join(", "),
            ),
            (
                "recorded_recipients",
                dispatch_status.recorded_recipients.join(", "),
            ),
            ("missing_recipients", missing_recipients),
            ("evidence_row_count", evidence_row_count.to_string()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_absent_owner_dispatch_evidence",
            "notifications.reminder.absentOwnerDispatch.action",
            Some(format!(
                "/v1/documents/generated/{}/dispatch-evidence",
                document.id
            )),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the sealed act's generated communication workflow.".to_owned(),
            "Record operator dispatch evidence for the missing absent recipients when available."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.absentOwnerDispatch.title",
            "notifications.reminder.absentOwnerDispatch.body",
            Some("notifications.reminder.absentOwnerDispatch.action"),
        )),
    }
}

fn privacy_control_review_reminders(
    breach_playbooks: &HashMap<BreachPlaybookId, BreachPlaybookRecord>,
    transfer_controls: &HashMap<TransferControlId, TransferControlRecord>,
    today: Date,
    due_soon_days: u16,
) -> Vec<DashboardReminder> {
    let breach_reminders = breach_playbooks.values().filter_map(|record| {
        if record.status == PrivacyRecordStatus::Retired {
            return None;
        }
        let review = breach_playbook_advisory_review(record, today, due_soon_days);
        privacy_review_reminder_from_summary(
            "privacy-breach-playbook-review",
            "privacy-breach-playbook",
            &record.id.to_string(),
            &record.title,
            record.status,
            &review.status,
            review.next_review_due_at.as_deref(),
            review.last_reviewed_at.as_deref(),
            review.last_drill_at.as_deref(),
            review.days_until_due,
            review.review_receipt_count,
            review.drill_receipt_count,
            review.receipt_count,
        )
    });
    let transfer_reminders = transfer_controls.values().filter_map(|record| {
        if record.status == PrivacyRecordStatus::Retired {
            return None;
        }
        let review = transfer_control_advisory_review(record, today, due_soon_days);
        privacy_review_reminder_from_summary(
            "privacy-transfer-control-review",
            "privacy-transfer-control",
            &record.id.to_string(),
            &record.name,
            record.status,
            &review.status,
            review.next_review_due_at.as_deref(),
            review.last_reviewed_at.as_deref(),
            None,
            review.days_until_due,
            review.review_receipt_count,
            review.drill_receipt_count,
            review.receipt_count,
        )
    });

    breach_reminders.chain(transfer_reminders).collect()
}

#[allow(clippy::too_many_arguments)]
fn privacy_review_reminder_from_summary(
    source_rule: &str,
    source_profile: &str,
    record_id: &str,
    record_label: &str,
    record_status: PrivacyRecordStatus,
    review_status: &PrivacyAdvisoryReviewStatus,
    next_review_due_at: Option<&str>,
    last_reviewed_at: Option<&str>,
    last_drill_at: Option<&str>,
    days_until_due: Option<i32>,
    review_receipt_count: usize,
    drill_receipt_count: usize,
    receipt_count: usize,
) -> Option<DashboardReminder> {
    let (dashboard_status, severity, reason_prefix) = match review_status {
        PrivacyAdvisoryReviewStatus::NoReceipt => (
            "Pending",
            "Advisory",
            "has no local review or drill receipt recorded",
        ),
        PrivacyAdvisoryReviewStatus::DueSoon => {
            ("DueSoon", "Info", "has a local advisory review due soon")
        }
        PrivacyAdvisoryReviewStatus::Overdue => {
            ("Overdue", "Warning", "has an overdue local advisory review")
        }
        PrivacyAdvisoryReviewStatus::UnderReview => ("Pending", "Info", "is marked under review"),
        PrivacyAdvisoryReviewStatus::Current => return None,
    };
    let next_due_text = next_review_due_at.unwrap_or("");
    let due_phrase = if next_due_text.is_empty() {
        "No next review date is derived because no local review cadence anchor exists.".to_owned()
    } else {
        format!("Next derived local review date is {next_due_text}.")
    };
    let last_activity = last_reviewed_at
        .or(last_drill_at)
        .unwrap_or("no local review/drill receipt");

    Some(DashboardReminder {
        due_date: next_due_text.to_owned(),
        severity: severity.to_owned(),
        status: dashboard_status.to_owned(),
        reason: format!(
            "Privacy register item \"{record_label}\" {reason_prefix}. {due_phrase} \
             This dashboard reminder is local and advisory only; it does not notify authorities \
             or subjects, approve or execute transfers, certify adequacy, or claim legal completion."
        ),
        entity_id: "privacy".to_owned(),
        entity_name: "Privacidade".to_owned(),
        source_rule: source_rule.to_owned(),
        source_profile: source_profile.to_owned(),
        params: dashboard_alert_params([
            ("record_id", record_id.to_owned()),
            ("record_label", record_label.to_owned()),
            ("record_status", format!("{record_status:?}")),
            ("review_status", format!("{review_status:?}")),
            ("next_review_due_at", next_due_text.to_owned()),
            ("last_local_activity_at", last_activity.to_owned()),
            (
                "last_reviewed_at",
                last_reviewed_at.unwrap_or_default().to_owned(),
            ),
            (
                "last_drill_at",
                last_drill_at.unwrap_or_default().to_owned(),
            ),
            (
                "days_until_due",
                days_until_due
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ),
            ("receipt_count", receipt_count.to_string()),
            ("review_receipt_count", review_receipt_count.to_string()),
            ("drill_receipt_count", drill_receipt_count.to_string()),
            ("local_advisory_only", "true".to_owned()),
            ("authority_notification_claimed", "false".to_owned()),
            ("subject_notification_claimed", "false".to_owned()),
            ("transfer_approval_claimed", "false".to_owned()),
            ("transfer_execution_claimed", "false".to_owned()),
            ("external_delivery_configured", "false".to_owned()),
            ("legal_completion_claimed", "false".to_owned()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_privacy_review",
            "notifications.reminder.privacy.review.action",
            Some(
                match source_profile {
                    "privacy-breach-playbook" => "/v1/privacy/breach-playbooks",
                    "privacy-transfer-control" => "/v1/privacy/transfer-controls",
                    _ => "/v1/privacy",
                }
                .to_owned(),
            ),
            Some("/configuracoes?sec=privacidade".to_owned()),
        )),
        recommended_next_steps: vec![
            "Open the privacy register item.".to_owned(),
            "Record a local review or drill receipt when operator evidence exists.".to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.privacy.review.title",
            "notifications.reminder.privacy.review.body",
            Some("notifications.reminder.privacy.review.action"),
        )),
    })
}

fn follow_up_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    follow_up: &StoredFollowUp,
    due_date: Date,
    today: Date,
    due_soon_days: u16,
) -> DashboardReminder {
    let due_date_text = format_date(due_date);
    let status = reminder_status(today, due_date, due_soon_days).to_owned();
    let severity = match status.as_str() {
        "Overdue" => "Warning",
        "DueSoon" => "Info",
        _ => "Advisory",
    }
    .to_owned();
    let detail = follow_up
        .detail
        .as_deref()
        .map(str::trim)
        .filter(|detail| !detail.is_empty());
    let assignee_display = follow_up
        .assignee_display
        .as_deref()
        .or(follow_up.assignee.as_deref())
        .map(str::trim)
        .filter(|assignee| !assignee.is_empty())
        .unwrap_or("");
    let body_key = if detail.is_some() {
        "notifications.reminder.followUp.body"
    } else {
        "notifications.reminder.followUp.bodyNoDetail"
    };
    let reason = match detail {
        Some(detail) => format!(
            "Follow-up \"{}\" for act \"{}\" is due on {}. {}",
            follow_up.title, act.title, due_date_text, detail
        ),
        None => format!(
            "Follow-up \"{}\" for act \"{}\" is due on {}.",
            follow_up.title, act.title, due_date_text
        ),
    };

    DashboardReminder {
        due_date: due_date_text.clone(),
        severity,
        status,
        reason,
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "act-follow-up".to_owned(),
        source_profile: format!("follow-up:{}", follow_up.id),
        params: dashboard_alert_params([
            ("follow_up_id", follow_up.id.clone()),
            ("follow_up_title", follow_up.title.clone()),
            (
                "follow_up_detail",
                detail.map(str::to_owned).unwrap_or_default(),
            ),
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("due_date", due_date_text),
            ("assignee", follow_up.assignee.clone().unwrap_or_default()),
            ("assignee_display", assignee_display.to_owned()),
            (
                "agenda_number",
                follow_up
                    .agenda_number
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ),
            (
                "deliberation_index",
                follow_up
                    .deliberation_index
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_act_follow_up",
            "notifications.reminder.followUp.action",
            Some(format!("/v1/acts/{}/follow-ups", act.id)),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the act follow-up list.".to_owned(),
            "Complete the follow-up row when the task is done.".to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.followUp.title",
            body_key,
            Some("notifications.reminder.followUp.action"),
        )),
    }
}

fn annual_general_meeting_reminders(
    entity: &Entity,
    context: &ProfileCalendarReminderContext<'_>,
) -> Vec<DashboardReminder> {
    if !entity.is_consistent() || !supports_profile_calendar_plan(entity.kind) {
        return Vec::new();
    }

    let plan = profile_calendar_plan_for(entity.kind);
    plan.rules
        .iter()
        .filter_map(|preset| profile_calendar_reminder(entity, &plan, preset, context))
        .collect()
}

struct ProfileCalendarReminderContext<'a> {
    books: &'a HashMap<BookId, Book>,
    acts: &'a HashMap<ActId, Act>,
    registry_extract: Option<&'a RegistryExtract>,
    today: Date,
    due_soon_days: u16,
}

fn profile_calendar_reminder(
    entity: &Entity,
    plan: &ProfileCalendarPlan,
    preset: &CalendarPreset,
    context: &ProfileCalendarReminderContext<'_>,
) -> Option<DashboardReminder> {
    let evaluation = evaluate_profile_calendar_rule(
        preset,
        ProfileCalendarEvaluationContext {
            today: context.today,
            recorded_fiscal_year_end: entity.fiscal_year_end.as_deref(),
            constitution_date: registry_constitution_date(context.registry_extract),
        },
    );

    match evaluation {
        ProfileCalendarRuleEvaluation::Scheduled(scheduled) => {
            if has_recent_calendar_signal(
                entity,
                context.books,
                context.acts,
                scheduled.due_date.year(),
            ) {
                return None;
            }
            Some(supported_profile_calendar_advisory(
                entity, plan, preset, scheduled, context,
            ))
        }
        ProfileCalendarRuleEvaluation::Unsupported(unsupported) => Some(
            unsupported_profile_calendar_advisory(entity, plan, preset, unsupported),
        ),
        ProfileCalendarRuleEvaluation::Suppressed(_) => None,
    }
}

fn supported_profile_calendar_advisory(
    entity: &Entity,
    plan: &ProfileCalendarPlan,
    preset: &CalendarPreset,
    scheduled: ProfileCalendarScheduledRule,
    context: &ProfileCalendarReminderContext<'_>,
) -> DashboardReminder {
    let due_date = scheduled.due_date;
    let params = supported_profile_calendar_params(preset, scheduled);
    DashboardReminder {
        due_date: format_date(due_date),
        severity: "Advisory".to_owned(),
        status: reminder_status(context.today, due_date, context.due_soon_days).to_owned(),
        reason: format!(
            "The {} calendar preset \"{}\" produces a local advisory date of {} \
             ({}). \
             No sealed or archived {} act dated {} is recorded for this entity. \
             Chancela does not claim a legal deadline, legal calendar authority, or legal \
             compliance from this local plan.",
            family_calendar_label(plan.family),
            preset.label,
            format_date(due_date),
            scheduled.due_basis.reason_fragment(),
            calendar_signal_label(plan.family),
            due_date.year()
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: preset.id.to_owned(),
        source_profile: plan.template_family.to_owned(),
        params,
        profile_calendar_plan: Some(supported_profile_calendar_plan_view(preset, scheduled)),
        law_refs: calendar_law_refs(preset),
        action: Some(dashboard_action(
            "open_entity",
            "notifications.reminder.annual.action",
            Some(format!("/v1/entities/{}", entity.id)),
            Some(format!("/entidades/{}", entity.id)),
        )),
        recommended_next_steps: calendar_next_steps(plan.family),
        i18n: None,
    }
}

fn unsupported_profile_calendar_advisory(
    entity: &Entity,
    plan: &ProfileCalendarPlan,
    preset: &CalendarPreset,
    unsupported: ProfileCalendarUnsupportedRule,
) -> DashboardReminder {
    let params = unsupported_profile_calendar_params(preset, unsupported);

    DashboardReminder {
        due_date: String::new(),
        severity: "Advisory".to_owned(),
        status: "Pending".to_owned(),
        reason: format!(
            "The {} calendar preset \"{}\" is encoded in the entity profile, but no local \
             due-date rule or fiscal-year offset is configured/encoded for it. Chancela does \
             not calculate a legal deadline for this preset; this advisory only makes the \
             unsupported preset visible.",
            family_calendar_label(plan.family),
            preset.label
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: preset.id.to_owned(),
        source_profile: plan.template_family.to_owned(),
        params,
        profile_calendar_plan: Some(unsupported_profile_calendar_plan_view(preset, unsupported)),
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_entity",
            "notifications.reminder.annual.action",
            Some(format!("/v1/entities/{}", entity.id)),
            Some(format!("/entidades/{}", entity.id)),
        )),
        recommended_next_steps: vec![
            "Review the encoded profile calendar preset manually.".to_owned(),
            "Add a local due-date rule only after the calendar rule is verified and encoded."
                .to_owned(),
        ],
        i18n: None,
    }
}

fn supported_profile_calendar_params(
    preset: &CalendarPreset,
    scheduled: ProfileCalendarScheduledRule,
) -> BTreeMap<String, String> {
    let mut params = profile_calendar_preset_params(preset, true, true, false);
    if let Some(months_after_fiscal_year_end) = scheduled.months_after_fiscal_year_end {
        params.insert(
            "months_after_fiscal_year_end".to_owned(),
            months_after_fiscal_year_end.to_string(),
        );
    }
    if let Some(fiscal_year_end) = scheduled.fiscal_year_end {
        params.insert("fiscal_year_end".to_owned(), fiscal_year_end.format_mm_dd());
    }
    if let Some(annual_fixed_date) = scheduled.annual_fixed_date {
        params.insert(
            "annual_fixed_month".to_owned(),
            annual_fixed_date.month.to_string(),
        );
        params.insert(
            "annual_fixed_day".to_owned(),
            annual_fixed_date.day.to_string(),
        );
    }
    params.insert("due_year".to_owned(), scheduled.due_date.year().to_string());
    params.insert(
        "due_basis".to_owned(),
        scheduled.due_basis.as_str().to_owned(),
    );
    params
}

fn unsupported_profile_calendar_params(
    preset: &CalendarPreset,
    unsupported: ProfileCalendarUnsupportedRule,
) -> BTreeMap<String, String> {
    let mut params = profile_calendar_preset_params(preset, false, false, false);
    params.insert(
        "unsupported_reason".to_owned(),
        unsupported.reason.as_str().to_owned(),
    );
    params
}

fn profile_calendar_preset_params(
    preset: &CalendarPreset,
    local_due_date_rule_configured: bool,
    local_due_date_calculated: bool,
    legal_deadline_calculated: bool,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    params.insert(
        "calendar_preset_support".to_owned(),
        preset.support_status.as_str().to_owned(),
    );
    params.insert("preset_id".to_owned(), preset.id.to_owned());
    params.insert("preset_label".to_owned(), preset.label.to_owned());
    params.insert("rule_kind".to_owned(), preset.rule_kind.as_str().to_owned());
    params.insert(
        "review_status".to_owned(),
        preset.review_status.as_str().to_owned(),
    );
    params.insert(
        "source_status".to_owned(),
        preset.source_status.as_str().to_owned(),
    );
    params.insert(
        "local_due_date_rule_configured".to_owned(),
        local_due_date_rule_configured.to_string(),
    );
    params.insert(
        "local_due_date_calculated".to_owned(),
        local_due_date_calculated.to_string(),
    );
    params.insert(
        "legal_deadline_calculated".to_owned(),
        legal_deadline_calculated.to_string(),
    );
    insert_profile_calendar_no_claim_params(&mut params, preset.no_claims);
    params
}

fn insert_profile_calendar_no_claim_params(
    params: &mut BTreeMap<String, String>,
    no_claims: ProfileCalendarNoClaimFlags,
) {
    params.insert(
        "local_advisory_only".to_owned(),
        no_claims.local_advisory_only.to_string(),
    );
    params.insert(
        "legal_deadline_authority_claimed".to_owned(),
        no_claims.legal_deadline_authority_claimed.to_string(),
    );
    params.insert(
        "legal_calendar_authority_claimed".to_owned(),
        no_claims.legal_calendar_authority_claimed.to_string(),
    );
    params.insert(
        "legal_compliance_claimed".to_owned(),
        no_claims.legal_compliance_claimed.to_string(),
    );
    params.insert(
        "compliance_status_claimed".to_owned(),
        no_claims.compliance_status_claimed.to_string(),
    );
    params.insert(
        "workflow_completion_claimed".to_owned(),
        no_claims.workflow_completion_claimed.to_string(),
    );
    params.insert(
        "external_delivery_claimed".to_owned(),
        no_claims.external_delivery_claimed.to_string(),
    );
    params.insert(
        "external_calendar_sync_claimed".to_owned(),
        no_claims.external_calendar_sync_claimed.to_string(),
    );
    params.insert(
        "webhook_delivery_claimed".to_owned(),
        no_claims.webhook_delivery_claimed.to_string(),
    );
    params.insert(
        "legal_review_claimed".to_owned(),
        no_claims.legal_review_claimed.to_string(),
    );
    params.insert(
        "dre_verification_claimed".to_owned(),
        no_claims.dre_verification_claimed.to_string(),
    );
    params.insert(
        "provider_effect_claimed".to_owned(),
        no_claims.provider_effect_claimed.to_string(),
    );
    params.insert(
        "certification_claimed".to_owned(),
        no_claims.certification_claimed.to_string(),
    );
}

fn supported_profile_calendar_plan_view(
    preset: &CalendarPreset,
    scheduled: ProfileCalendarScheduledRule,
) -> DashboardProfileCalendarPlan {
    profile_calendar_plan_view(
        preset,
        DashboardProfileCalendarEvaluation {
            local_due_date_rule_configured: true,
            local_due_date_calculated: true,
            legal_deadline_calculated: false,
            fiscal_year_end: scheduled
                .fiscal_year_end
                .map(|fiscal_year_end| fiscal_year_end.format_mm_dd()),
            due_year: Some(scheduled.due_date.year()),
            due_basis: Some(scheduled.due_basis.as_str().to_owned()),
            unsupported_reason: None,
        },
    )
}

fn unsupported_profile_calendar_plan_view(
    preset: &CalendarPreset,
    unsupported: ProfileCalendarUnsupportedRule,
) -> DashboardProfileCalendarPlan {
    profile_calendar_plan_view(
        preset,
        DashboardProfileCalendarEvaluation {
            local_due_date_rule_configured: false,
            local_due_date_calculated: false,
            legal_deadline_calculated: false,
            fiscal_year_end: None,
            due_year: None,
            due_basis: None,
            unsupported_reason: Some(unsupported.reason.as_str().to_owned()),
        },
    )
}

fn profile_calendar_plan_view(
    preset: &CalendarPreset,
    evaluation: DashboardProfileCalendarEvaluation,
) -> DashboardProfileCalendarPlan {
    DashboardProfileCalendarPlan {
        preset_id: preset.id.to_owned(),
        preset_label: preset.label.to_owned(),
        rule_kind: preset.rule_kind.as_str().to_owned(),
        support_status: preset.support_status.as_str().to_owned(),
        review_status: preset.review_status.as_str().to_owned(),
        source_status: preset.source_status.as_str().to_owned(),
        due_rule: profile_calendar_due_rule_view(preset),
        evaluation,
        no_claims: dashboard_profile_calendar_no_claims(preset.no_claims),
    }
}

fn profile_calendar_due_rule_view(preset: &CalendarPreset) -> DashboardProfileCalendarDueRule {
    match preset.due_rule {
        ProfileCalendarDueRule::FiscalYearEndOffset {
            months_after_fiscal_year_end,
            default_fiscal_year_end,
        } => DashboardProfileCalendarDueRule {
            kind: preset.due_rule.kind().to_owned(),
            months_after_fiscal_year_end: Some(months_after_fiscal_year_end),
            default_fiscal_year_end: Some(default_fiscal_year_end.format_mm_dd()),
            annual_fixed_month: None,
            annual_fixed_day: None,
            unsupported_reason: None,
        },
        ProfileCalendarDueRule::AnnualFixedDate { month, day } => DashboardProfileCalendarDueRule {
            kind: preset.due_rule.kind().to_owned(),
            months_after_fiscal_year_end: None,
            default_fiscal_year_end: None,
            annual_fixed_month: Some(month),
            annual_fixed_day: Some(day),
            unsupported_reason: None,
        },
        ProfileCalendarDueRule::NotEncoded { reason } => DashboardProfileCalendarDueRule {
            kind: preset.due_rule.kind().to_owned(),
            months_after_fiscal_year_end: None,
            default_fiscal_year_end: None,
            annual_fixed_month: None,
            annual_fixed_day: None,
            unsupported_reason: Some(reason.as_str().to_owned()),
        },
    }
}

fn dashboard_profile_calendar_no_claims(
    no_claims: ProfileCalendarNoClaimFlags,
) -> DashboardProfileCalendarNoClaimFlags {
    DashboardProfileCalendarNoClaimFlags {
        local_advisory_only: no_claims.local_advisory_only,
        legal_deadline_authority_claimed: no_claims.legal_deadline_authority_claimed,
        legal_calendar_authority_claimed: no_claims.legal_calendar_authority_claimed,
        legal_compliance_claimed: no_claims.legal_compliance_claimed,
        compliance_status_claimed: no_claims.compliance_status_claimed,
        workflow_completion_claimed: no_claims.workflow_completion_claimed,
        external_delivery_claimed: no_claims.external_delivery_claimed,
        external_calendar_sync_claimed: no_claims.external_calendar_sync_claimed,
        webhook_delivery_claimed: no_claims.webhook_delivery_claimed,
        legal_review_claimed: no_claims.legal_review_claimed,
        dre_verification_claimed: no_claims.dre_verification_claimed,
        provider_effect_claimed: no_claims.provider_effect_claimed,
        certification_claimed: no_claims.certification_claimed,
    }
}

fn calendar_law_refs(preset: &CalendarPreset) -> Vec<DashboardLawReference> {
    preset
        .law_refs
        .iter()
        .map(|law_ref| DashboardLawReference {
            diploma_id: law_ref.diploma_id.to_owned(),
            article: law_ref.article.to_owned(),
            label: law_ref.label.to_owned(),
            heading: String::new(),
            verification: law_ref.source_status.dashboard_verification().to_owned(),
            source_url: None,
            source_complete: false,
            // Calendar-preset refs carry only their preset source-status, never corpus provenance.
            review_method: None,
            review_note: None,
        })
        .collect()
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

fn registry_constitution_date(registry_extract: Option<&RegistryExtract>) -> Option<Date> {
    let constitution_date = registry_extract?.effective_data_constituicao()?;
    parse_dashboard_date(&constitution_date)
}

fn reminder_status(today: Date, due_date: Date, due_soon_days: u16) -> &'static str {
    if today > due_date {
        return "Overdue";
    }
    let days_until = due_date.to_julian_day() - today.to_julian_day();
    if days_until <= i32::from(due_soon_days) {
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
    use crate::backup_recovery::{
        BackupRecoveryDrillIsolatedRestoreVerification, BackupRecoveryDrillReceipt,
    };
    use crate::privacy::{
        BreachEvidenceKind, BreachPlaybookEvidenceReceipt, PrivacyRiskLevel,
        TransferControlEvidenceReceipt,
    };
    use crate::settings::{BackupRecoveryPolicySettings, WorkflowReminderSourceSettings};
    use chancela_core::{
        AttendanceWeight, Attendee, Convening, LegalHold, MeetingChannel, Nipc, NumberingScheme,
        PresenceMode, SignatoryCapacity, StatuteOverrides, TermoDeAbertura,
    };
    use chancela_registry::{RegistryExtract, RegistryOfficer, RegistryProvenance};
    use time::macros::date;
    use uuid::Uuid;

    struct ReminderFixture {
        entities: HashMap<EntityId, Entity>,
        books: HashMap<BookId, Book>,
        acts: HashMap<ActId, Act>,
        follow_ups: HashMap<String, StoredFollowUp>,
        registry_extracts: HashMap<EntityId, RegistryExtract>,
    }

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

    fn reminder_fixture() -> ReminderFixture {
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Open;

        let mut act = Act::draft(
            book.id,
            "Ata com presencas e seguimento",
            MeetingChannel::Physical,
        );
        act.state = ActState::Review;
        act.meeting_date = Some(date!(2026 - 07 - 20));
        let follow_up = StoredFollowUp {
            id: "follow-up-open".to_owned(),
            act_id: act.id,
            agenda_number: Some(1),
            deliberation_index: Some(0),
            title: "Enviar certidão ao contabilista".to_owned(),
            detail: Some("Confirmar envio depois da revisão.".to_owned()),
            due_date: Some(date!(2026 - 07 - 01)),
            assignee: Some("ana".to_owned()),
            assignee_display: Some("Ana Silva".to_owned()),
            status: StoredFollowUpStatus::Open,
            created_at: OffsetDateTime::UNIX_EPOCH,
            created_by: "operator".to_owned(),
            completed_at: None,
            completed_by: None,
        };

        ReminderFixture {
            entities: HashMap::from([(entity.id, entity.clone())]),
            books: HashMap::from([(book.id, book)]),
            acts: HashMap::from([(act.id, act)]),
            follow_ups: HashMap::from([(follow_up.id.clone(), follow_up)]),
            registry_extracts: HashMap::new(),
        }
    }

    fn reminders_for_policy(
        fixture: &ReminderFixture,
        policy: &WorkflowReminderSettings,
    ) -> Vec<DashboardReminder> {
        dashboard_reminders_with_follow_ups(
            &fixture.entities,
            &fixture.books,
            &fixture.acts,
            &fixture.follow_ups,
            &fixture.registry_extracts,
            date!(2026 - 07 - 09),
            policy,
        )
    }

    fn imported_document_meta(
        id: &str,
        act_id: Option<ActId>,
        status: StoredImportedDocumentReviewStatus,
    ) -> StoredImportedDocumentMeta {
        StoredImportedDocumentMeta {
            id: id.to_owned(),
            act_id,
            filename: Some("sensitive-source-name.pdf".to_owned()),
            declared_content_type: Some("application/pdf".to_owned()),
            detected_content_type: "application/pdf".to_owned(),
            sha256: "secret-digest-that-must-not-surface".to_owned(),
            size_bytes: 2048,
            imported_at: OffsetDateTime::UNIX_EPOCH,
            imported_by: "sensitive.importer".to_owned(),
            operator_review_status: status,
            operator_reviewed_at: None,
            operator_reviewed_by: Some("sensitive.reviewer".to_owned()),
            operator_review_note: Some("sensitive operator note".to_owned()),
            operator_acknowledged_guardrail_ids: Vec::new(),
        }
    }

    fn source_rules(reminders: &[DashboardReminder]) -> Vec<String> {
        reminders
            .iter()
            .map(|reminder| reminder.source_rule.clone())
            .collect()
    }

    fn has_source_rule(rules: &[String], expected: &str) -> bool {
        rules.iter().any(|rule| rule == expected)
    }

    fn backup_recovery_receipt(
        id: &str,
        created_at: &str,
        archive: &str,
        ready: bool,
        isolated_verified: bool,
        isolated_status: &str,
    ) -> BackupRecoveryDrillReceipt {
        BackupRecoveryDrillReceipt {
            id: id.to_owned(),
            created_at: created_at.to_owned(),
            archive: archive.to_owned(),
            preflight_ok: ready,
            preflight_ready: ready,
            encrypted: Some(false),
            ledger_verified: ready,
            manifest: None,
            isolated_restore_verified: isolated_verified,
            isolated_restore_verification: BackupRecoveryDrillIsolatedRestoreVerification {
                status: isolated_status.to_owned(),
                db_snapshot_materialized: isolated_verified,
                db_snapshot_opened: isolated_verified,
                state_loaded: isolated_verified,
                ledger_verified: isolated_verified,
                cleanup_verified: isolated_verified,
                ..BackupRecoveryDrillIsolatedRestoreVerification::default()
            },
            operator_notes: Some("sensitive operator note".to_owned()),
            custody_location: Some("sensitive custody shelf".to_owned()),
            restore_executed: false,
            live_db_swapped: false,
            sidecars_staged: false,
            ledger_restored_appended: false,
            data_deleted: false,
            offsite_custody_proven: false,
            legal_archive_certified: false,
        }
    }

    fn verified_backup_recovery_receipt(
        id: &str,
        created_at: &str,
        archive: &str,
    ) -> BackupRecoveryDrillReceipt {
        backup_recovery_receipt(id, created_at, archive, true, true, "verified")
    }

    #[test]
    fn backup_recovery_freshness_alerts_cover_unfresh_states_without_receipt_internals() {
        let policy = BackupRecoveryPolicySettings::default();
        let now = OffsetDateTime::parse("2026-07-14T12:00:00Z", &Rfc3339).expect("fixed now");

        let no_receipt = backup_recovery_freshness_review(&[], policy.clone(), now);
        let no_receipt_alert =
            backup_recovery_freshness_alert(&no_receipt).expect("no-receipt alert");
        assert_eq!(no_receipt_alert.code, "backup.recovery.freshness_advisory");
        assert_eq!(no_receipt_alert.label, "Advisory");
        assert_eq!(no_receipt_alert.category, "BackupRecoveryFreshness");
        assert_eq!(
            no_receipt_alert
                .params
                .get("freshness_status")
                .map(String::as_str),
            Some("no_receipt")
        );
        assert_eq!(
            no_receipt_alert
                .params
                .get("policy_max_drill_age_days")
                .map(String::as_str),
            Some("90")
        );
        assert_eq!(
            no_receipt_alert
                .params
                .get("latest_receipt_at")
                .map(String::as_str),
            Some("not_recorded")
        );
        assert_eq!(
            no_receipt_alert
                .params
                .get("latest_receipt_preflight_ready")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            no_receipt_alert
                .params
                .get("latest_receipt_isolated_restore_verified")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            no_receipt_alert
                .action
                .as_ref()
                .and_then(|action| action.route.as_deref()),
            Some("/configuracoes?sec=dados")
        );

        let stale_receipts = vec![verified_backup_recovery_receipt(
            "stale-receipt-secret-id",
            "2000-01-01T00:00:00Z",
            "backups/stale-secret-archive.zip",
        )];
        let stale = backup_recovery_freshness_review(&stale_receipts, policy.clone(), now);
        assert!(matches!(stale.status, BackupRecoveryFreshnessStatus::Stale));
        let stale_alert = backup_recovery_freshness_alert(&stale).expect("stale alert");
        assert_eq!(
            stale_alert
                .params
                .get("freshness_status")
                .map(String::as_str),
            Some("stale")
        );
        assert_eq!(
            stale_alert
                .params
                .get("latest_receipt_at")
                .map(String::as_str),
            Some("2000-01-01T00:00:00Z")
        );
        assert_eq!(
            stale_alert
                .params
                .get("latest_receipt_preflight_ready")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            stale_alert
                .params
                .get("latest_receipt_isolated_restore_verified")
                .map(String::as_str),
            Some("true")
        );

        let failed_receipts = vec![backup_recovery_receipt(
            "failed-receipt-secret-id",
            "2026-07-14T10:00:00Z",
            "backups/failed-secret-archive.zip",
            false,
            false,
            "failed",
        )];
        let failed = backup_recovery_freshness_review(&failed_receipts, policy.clone(), now);
        assert!(matches!(
            failed.status,
            BackupRecoveryFreshnessStatus::Failed
        ));
        let failed_alert = backup_recovery_freshness_alert(&failed).expect("failed alert");
        assert_eq!(
            failed_alert
                .params
                .get("freshness_status")
                .map(String::as_str),
            Some("failed")
        );
        assert_eq!(
            failed_alert
                .params
                .get("latest_receipt_preflight_ready")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            failed_alert
                .params
                .get("latest_receipt_isolated_restore_verified")
                .map(String::as_str),
            Some("false")
        );

        let fresh_receipts = vec![verified_backup_recovery_receipt(
            "fresh-receipt-secret-id",
            "2026-07-14T10:00:00Z",
            "backups/fresh-secret-archive.zip",
        )];
        let fresh = backup_recovery_freshness_review(&fresh_receipts, policy, now);
        assert!(matches!(fresh.status, BackupRecoveryFreshnessStatus::Fresh));
        assert!(
            backup_recovery_freshness_alert(&fresh).is_none(),
            "fresh recovery drill receipts must not create a dashboard alert"
        );

        for alert in [no_receipt_alert, stale_alert, failed_alert] {
            assert!(!alert.params.contains_key("latest_receipt_id"));
            assert!(!alert.params.contains_key("archive"));
            assert!(!alert.params.contains_key("manifest"));
            assert!(!alert.params.contains_key("findings"));
            let serialized = serde_json::to_string(&alert).expect("alert serializes");
            for forbidden in [
                "secret-id",
                "secret-archive",
                "sensitive operator note",
                "sensitive custody shelf",
                "member_count",
                "restore_executed",
                "live_db_swapped",
            ] {
                assert!(
                    !serialized.contains(forbidden),
                    "dashboard alert leaked {forbidden}: {serialized}"
                );
            }
        }
    }

    /// The store collections plus generated-dispatch evidence a sealed-condominium reminder fixture
    /// hands back. Aliased so the builder's return type stays legible.
    type SealedCondominiumDispatchFixture = (
        HashMap<EntityId, Entity>,
        HashMap<BookId, Book>,
        HashMap<ActId, Act>,
        Vec<GeneratedDispatchEvidenceSnapshot>,
    );

    fn sealed_condominium_dispatch_fixture(
        evidence_recipients: &[&str],
    ) -> SealedCondominiumDispatchFixture {
        let entity = entity_of(EntityKind::Condominio);
        let mut book = Book::new(entity.id, BookKind::Condominio);
        book.state = BookState::Open;
        let mut act = Act::draft(
            book.id,
            "Ata da assembleia de condóminos",
            MeetingChannel::Physical,
        );
        act.state = ActState::Sealed;
        act.ata_number = Some(12);
        act.attendees = vec![
            Attendee {
                name: "Fração A".to_owned(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(520)),
            },
            Attendee {
                name: "Fração B".to_owned(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Absent,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(280)),
            },
            Attendee {
                name: "Fração C".to_owned(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Absent,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(200)),
            },
        ];
        let document = StoredDocument {
            id: "generated-absent-owner-1".to_owned(),
            act_id: act.id,
            template_id: crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID
                .to_owned(),
            pdf_digest: "ab".repeat(32),
            profile: crate::documents::PDFA_PROFILE.to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            pdf_bytes: b"%PDF-1.7\nabsent-owner-communication".to_vec(),
        };
        let evidence = if evidence_recipients.is_empty() {
            Vec::new()
        } else {
            vec![StoredGeneratedDocumentDispatchEvidence {
                document_id: document.id.clone(),
                idempotency_key: "dispatch-evidence-key-1".to_owned(),
                act_id: document.act_id,
                template_id: document.template_id.clone(),
                actor: "operator.fixture".to_owned(),
                dispatched_at: OffsetDateTime::UNIX_EPOCH,
                channel: Some("RegisteredLetter".to_owned()),
                reference: Some("RR123456789PT".to_owned()),
                evidence_reference: Some("archive:dispatch-proof-1".to_owned()),
                imported_document_id: None,
                recipients: evidence_recipients
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
                operator_note: Some("Operator-recorded external locator only.".to_owned()),
                recorded_at: OffsetDateTime::UNIX_EPOCH,
            }]
        };

        (
            HashMap::from([(entity.id, entity)]),
            HashMap::from([(book.id, book)]),
            HashMap::from([(act.id, act)]),
            vec![GeneratedDispatchEvidenceSnapshot { document, evidence }],
        )
    }

    fn reminders_for_generated_dispatch_evidence(
        evidence_recipients: &[&str],
    ) -> Vec<DashboardReminder> {
        let (entities, books, acts, generated_dispatch_evidence) =
            sealed_condominium_dispatch_fixture(evidence_recipients);
        dashboard_reminders_with_generated_dispatch_evidence(
            ReminderInputs {
                entities: &entities,
                books: &books,
                acts: &acts,
                follow_ups: &HashMap::new(),
                generated_dispatch_evidence: &generated_dispatch_evidence,
                imported_documents: &[],
                registry_extracts: &HashMap::new(),
                breach_playbooks: &HashMap::new(),
                transfer_controls: &HashMap::new(),
            },
            date!(2026 - 07 - 09),
            &WorkflowReminderSettings::default(),
        )
    }

    fn breach_playbook_record(
        id: &str,
        title: &str,
        status: PrivacyRecordStatus,
        receipts: Vec<BreachPlaybookEvidenceReceipt>,
    ) -> BreachPlaybookRecord {
        BreachPlaybookRecord {
            id: BreachPlaybookId(Uuid::parse_str(id).expect("uuid")),
            title: title.to_owned(),
            scope: "Local breach response rehearsal".to_owned(),
            detection_channels: vec!["support queue".to_owned()],
            containment_steps: vec!["isolate affected process".to_owned()],
            notification_roles: vec!["DPO".to_owned()],
            authority_notification_window: None,
            subject_notification_guidance: None,
            risk_level: PrivacyRiskLevel::High,
            status,
            review_notes: None,
            evidence_receipts: receipts,
            created_at: "2025-01-01T00:00:00Z".to_owned(),
            created_by: "operator".to_owned(),
            updated_at: "2025-01-01T00:00:00Z".to_owned(),
            updated_by: "operator".to_owned(),
        }
    }

    fn transfer_control_record(
        id: &str,
        name: &str,
        status: PrivacyRecordStatus,
        receipts: Vec<TransferControlEvidenceReceipt>,
    ) -> TransferControlRecord {
        TransferControlRecord {
            id: TransferControlId(Uuid::parse_str(id).expect("uuid")),
            name: name.to_owned(),
            purpose: "Operator review of transfer safeguards".to_owned(),
            legal_basis: "Contract necessity review".to_owned(),
            data_categories: vec!["member contacts".to_owned()],
            recipient: "Processor SA".to_owned(),
            destination_country: "PT".to_owned(),
            transfer_mechanism: "local review register".to_owned(),
            safeguards: vec!["least privilege".to_owned()],
            risk_level: PrivacyRiskLevel::Medium,
            status,
            review_notes: None,
            evidence_receipts: receipts,
            created_at: "2025-01-01T00:00:00Z".to_owned(),
            created_by: "operator".to_owned(),
            updated_at: "2025-01-01T00:00:00Z".to_owned(),
            updated_by: "operator".to_owned(),
        }
    }

    #[test]
    fn privacy_control_review_reminders_cover_missing_overdue_and_source_toggle() {
        let missing_breach = breach_playbook_record(
            "00000000-0000-4000-8000-000000000301",
            "Breach playbook without receipt",
            PrivacyRecordStatus::Active,
            Vec::new(),
        );
        let current_breach = breach_playbook_record(
            "00000000-0000-4000-8000-000000000302",
            "Current breach drill",
            PrivacyRecordStatus::Active,
            vec![BreachPlaybookEvidenceReceipt {
                id: "breach-drill-current".to_owned(),
                evidence_type: BreachEvidenceKind::Drill,
                recorded_at: "2026-06-01T00:00:00Z".to_owned(),
                recorded_by: "operator".to_owned(),
                occurred_at: None,
                notes: None,
                authority_notified: false,
                subjects_notified: false,
            }],
        );
        let overdue_transfer = transfer_control_record(
            "00000000-0000-4000-8000-000000000303",
            "Overdue transfer review",
            PrivacyRecordStatus::Active,
            vec![TransferControlEvidenceReceipt {
                id: "transfer-review-old".to_owned(),
                recorded_at: "2025-06-01T00:00:00Z".to_owned(),
                recorded_by: "operator".to_owned(),
                reviewed_at: Some("2025-06-01T00:00:00Z".to_owned()),
                notes: None,
                transfer_approved: false,
                data_transfer_executed: false,
            }],
        );
        let breach_playbooks = HashMap::from([
            (missing_breach.id, missing_breach),
            (current_breach.id, current_breach),
        ]);
        let transfer_controls = HashMap::from([(overdue_transfer.id, overdue_transfer)]);
        let policy = WorkflowReminderSettings {
            dashboard_limit: 10,
            ..WorkflowReminderSettings::default()
        };

        let reminders = dashboard_reminders_with_generated_dispatch_evidence(
            ReminderInputs {
                entities: &HashMap::new(),
                books: &HashMap::new(),
                acts: &HashMap::new(),
                follow_ups: &HashMap::new(),
                generated_dispatch_evidence: &[],
                imported_documents: &[],
                registry_extracts: &HashMap::new(),
                breach_playbooks: &breach_playbooks,
                transfer_controls: &transfer_controls,
            },
            date!(2026 - 07 - 09),
            &policy,
        );

        assert_eq!(reminders.len(), 2);
        assert!(reminders.iter().any(|reminder| {
            reminder.source_rule == "privacy-breach-playbook-review"
                && reminder.status == "Pending"
                && reminder.reason.contains("local and advisory only")
                && reminder
                    .params
                    .get("authority_notification_claimed")
                    .is_some_and(|value| value == "false")
        }));
        assert!(reminders.iter().any(|reminder| {
            reminder.source_rule == "privacy-transfer-control-review"
                && reminder.status == "Overdue"
                && reminder.due_date == "2026-06-01"
                && reminder
                    .params
                    .get("transfer_execution_claimed")
                    .is_some_and(|value| value == "false")
        }));
        assert!(reminders.iter().all(|reminder| reminder.source_profile
            != "privacy-breach-playbook"
            || reminder.params.get("record_label") != Some(&"Current breach drill".to_owned())));

        let disabled_policy = WorkflowReminderSettings {
            dashboard_limit: 10,
            sources: WorkflowReminderSourceSettings {
                privacy_control_reviews: false,
                ..WorkflowReminderSourceSettings::default()
            },
            ..WorkflowReminderSettings::default()
        };
        let disabled = dashboard_reminders_with_generated_dispatch_evidence(
            ReminderInputs {
                entities: &HashMap::new(),
                books: &HashMap::new(),
                acts: &HashMap::new(),
                follow_ups: &HashMap::new(),
                generated_dispatch_evidence: &[],
                imported_documents: &[],
                registry_extracts: &HashMap::new(),
                breach_playbooks: &breach_playbooks,
                transfer_controls: &transfer_controls,
            },
            date!(2026 - 07 - 09),
            &disabled_policy,
        );
        assert!(disabled.is_empty());
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
            required_signatory_records: Vec::new(),
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
        // csc:255 is now automated-review authentic text (wp22): a distinct honest tier, NOT
        // human-`Verified`, but backed by a complete source. The "no human approval without the
        // marker" invariant holds — it must never render as `Verified`.
        assert_eq!(alert.law_refs[0].verification, "automated_review");
        assert_ne!(alert.law_refs[0].verification, "Verified");
        assert!(alert.law_refs[0].source_complete);
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
        assert_eq!(
            alert.params.get("office").map(String::as_str),
            Some("management")
        );
        assert_eq!(
            alert.i18n.as_ref().map(|i18n| i18n.title_key.as_str()),
            Some("notifications.alert.entity.managerRemuneration.title")
        );
    }

    #[test]
    fn lifecycle_alerts_recommend_administrator_remuneration_setup_for_sa() {
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let entities = HashMap::from([(entity.id, entity.clone())]);
        let registry_extracts =
            HashMap::from([(entity.id, registry_extract_with_officer("Administrador"))]);

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
            .find(|alert| alert.code == "entity.administrator_remuneration.setup_recommended")
            .expect("administrator remuneration alert");
        assert_eq!(alert.severity, "Info");
        assert_eq!(alert.category, "GovernanceSetup");
        assert_eq!(alert.law_refs.len(), 1);
        assert_eq!(alert.law_refs[0].diploma_id, "csc");
        assert_eq!(alert.law_refs[0].article, "399");
        assert_eq!(alert.law_refs[0].heading, "Remuneração dos administradores");
        // csc:399 is now automated-review authentic text (wp22): NOT human-`Verified`, but sourced.
        assert_eq!(alert.law_refs[0].verification, "automated_review");
        assert_ne!(alert.law_refs[0].verification, "Verified");
        assert!(alert.law_refs[0].source_complete);
        // The automated-review tier carries its method + standing caveat so the client can badge it
        // honestly and show the "human legal review recommended" tooltip.
        assert_eq!(
            alert.law_refs[0].review_method.as_deref(),
            Some("automated-capture")
        );
        assert!(
            alert.law_refs[0]
                .review_note
                .as_deref()
                .is_some_and(|note| note.contains("Revisão automatizada")
                    && note.contains("NÃO aprovado juridicamente")),
            "automated-review ref carries the pt-PT human-approval caveat"
        );
        assert_eq!(
            alert.params.get("office").map(String::as_str),
            Some("administration")
        );
        assert_eq!(
            alert
                .action
                .as_ref()
                .map(|action| action.label_key.as_str()),
            Some("notifications.alert.entity.administratorRemuneration.action")
        );
        assert_eq!(
            alert.i18n.as_ref().map(|i18n| i18n.body_key.as_str()),
            Some("notifications.alert.entity.administratorRemuneration.body")
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
            required_signatory_records: Vec::new(),
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
    fn lifecycle_alerts_surface_legal_hold_and_unarchived_sealed_acts() {
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Open;
        book.termo_abertura = Some(TermoDeAbertura {
            entity_name: entity.name.clone(),
            entity_nipc: entity.nipc.as_str().to_owned(),
            entity_seat: entity.seat.clone(),
            purpose: "Livro de atas da assembleia geral".to_owned(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: date!(2026 - 01 - 05),
            required_signatories: vec!["Administração".to_owned()],
            required_signatory_records: Vec::new(),
        });
        book.legal_hold = Some(LegalHold {
            reason: "litigation hold".to_owned(),
            actor: "operator".to_owned(),
            set_at: OffsetDateTime::UNIX_EPOCH,
        });

        let mut sealed = Act::draft(book.id, "Ata selada", MeetingChannel::Physical);
        sealed.state = ActState::Sealed;
        let mut archived = Act::draft(book.id, "Ata arquivada", MeetingChannel::Physical);
        archived.state = ActState::Archived;
        let sealed_id = sealed.id;
        let archived_id = archived.id;
        let sealed_id_text = sealed_id.to_string();
        let archived_id_text = archived_id.to_string();
        let entities = HashMap::from([(entity.id, entity.clone())]);
        let books = HashMap::from([(book.id, book.clone())]);
        let acts = HashMap::from([(sealed.id, sealed), (archived.id, archived)]);

        let alerts = dashboard_alerts(
            &entities,
            &books,
            &acts,
            &HashMap::new(),
            true,
            date!(2026 - 07 - 09),
        );

        let hold = alerts
            .iter()
            .find(|alert| alert.code == "book.legal_hold.active")
            .expect("legal hold alert");
        assert_eq!(hold.label, "ReviewRequired");
        assert_eq!(hold.severity, "Warning");
        assert_eq!(hold.category, "ArchiveRetention");
        assert_eq!(
            hold.params.get("legal_hold_reason").map(String::as_str),
            Some("litigation hold")
        );
        assert_eq!(
            hold.params.get("legal_hold_actor").map(String::as_str),
            Some("operator")
        );
        assert_eq!(
            hold.params.get("legal_hold_set_at").map(String::as_str),
            Some("1970-01-01T00:00:00Z")
        );
        let expected_book_route = format!("/livros/{}", book.id);
        assert_eq!(
            hold.action
                .as_ref()
                .and_then(|action| action.route.as_deref()),
            Some(expected_book_route.as_str())
        );
        assert_eq!(
            hold.i18n.as_ref().map(|i18n| i18n.title_key.as_str()),
            Some("notifications.alert.book.legalHold.title")
        );

        let archive = alerts
            .iter()
            .find(|alert| alert.code == "act.archive.pending")
            .expect("archive-pending alert");
        assert_eq!(archive.label, "Advisory");
        assert_eq!(archive.severity, "Info");
        assert_eq!(archive.category, "ArchiveStatus");
        assert_eq!(
            archive.target.act_id.as_deref(),
            Some(sealed_id_text.as_str())
        );
        assert_eq!(
            archive
                .params
                .get("recommended_actions")
                .map(String::as_str),
            Some("archive_act")
        );
        let expected_act_route = format!("/atas/{sealed_id}");
        assert_eq!(
            archive
                .action
                .as_ref()
                .and_then(|action| action.route.as_deref()),
            Some(expected_act_route.as_str())
        );
        assert!(
            alerts
                .iter()
                .filter(|alert| alert.code == "act.archive.pending")
                .all(|alert| alert.target.act_id.as_deref() != Some(archived_id_text.as_str()))
        );
    }

    #[test]
    fn default_reminder_policy_preserves_existing_families() {
        let fixture = reminder_fixture();
        let reminders = reminders_for_policy(&fixture, &WorkflowReminderSettings::default());

        assert_eq!(
            source_rules(&reminders),
            [
                "csc-art376-annual".to_owned(),
                "act-follow-up".to_owned(),
                "act-attendance-missing".to_owned()
            ]
        );
        assert_eq!(reminders.len(), 3);
    }

    #[test]
    fn disabled_reminder_policy_suppresses_only_reminder_output() {
        let fixture = reminder_fixture();
        let current_work = dashboard_current_work(&fixture.entities, &fixture.books, &fixture.acts);
        let policy = WorkflowReminderSettings {
            enabled: false,
            ..WorkflowReminderSettings::default()
        };

        let reminders = reminders_for_policy(&fixture, &policy);

        assert!(reminders.is_empty());
        assert_eq!(current_work.open_books.len(), 1);
        assert_eq!(current_work.act_counts_by_state.review, 1);
    }

    #[test]
    fn reminder_source_toggles_suppress_only_their_family() {
        let fixture = reminder_fixture();

        let policy = WorkflowReminderSettings {
            sources: WorkflowReminderSourceSettings {
                profile_calendar: false,
                ..WorkflowReminderSourceSettings::default()
            },
            ..WorkflowReminderSettings::default()
        };
        let rules = source_rules(&reminders_for_policy(&fixture, &policy));
        assert!(!has_source_rule(&rules, "csc-art376-annual"));
        assert!(has_source_rule(&rules, "act-follow-up"));
        assert!(has_source_rule(&rules, "act-attendance-missing"));

        let policy = WorkflowReminderSettings {
            sources: WorkflowReminderSourceSettings {
                act_follow_ups: false,
                ..WorkflowReminderSourceSettings::default()
            },
            ..WorkflowReminderSettings::default()
        };
        let rules = source_rules(&reminders_for_policy(&fixture, &policy));
        assert!(has_source_rule(&rules, "csc-art376-annual"));
        assert!(!has_source_rule(&rules, "act-follow-up"));
        assert!(has_source_rule(&rules, "act-attendance-missing"));

        let policy = WorkflowReminderSettings {
            sources: WorkflowReminderSourceSettings {
                attendance_hygiene: false,
                ..WorkflowReminderSourceSettings::default()
            },
            ..WorkflowReminderSettings::default()
        };
        let rules = source_rules(&reminders_for_policy(&fixture, &policy));
        assert!(has_source_rule(&rules, "csc-art376-annual"));
        assert!(has_source_rule(&rules, "act-follow-up"));
        assert!(!has_source_rule(&rules, "act-attendance-missing"));
    }

    #[test]
    fn imported_document_review_reminder_surfaces_act_scoped_pending_imports_safely() {
        let fixture = reminder_fixture();
        let act = fixture.acts.values().next().expect("fixture act");
        let imports = vec![
            imported_document_meta(
                "11111111-1111-4111-8111-111111111111",
                Some(act.id),
                StoredImportedDocumentReviewStatus::OperatorReviewRequired,
            ),
            imported_document_meta(
                "22222222-2222-4222-8222-222222222222",
                Some(act.id),
                StoredImportedDocumentReviewStatus::OcrReviewRequired,
            ),
            imported_document_meta(
                "33333333-3333-4333-8333-333333333333",
                Some(act.id),
                StoredImportedDocumentReviewStatus::CanonicalConversionReviewRequired,
            ),
            imported_document_meta(
                "44444444-4444-4444-8444-444444444444",
                None,
                StoredImportedDocumentReviewStatus::OperatorReviewRequired,
            ),
            imported_document_meta(
                "55555555-5555-4555-8555-555555555555",
                Some(act.id),
                StoredImportedDocumentReviewStatus::ReviewedNonCanonicalOriginalOnly,
            ),
        ];

        let reminders = imported_document_review_reminders(
            &fixture.entities,
            &fixture.books,
            &fixture.acts,
            &imports,
        );

        assert_eq!(reminders.len(), 3);
        assert_eq!(
            reminders
                .iter()
                .map(|reminder| reminder.params["operator_review_status"].as_str())
                .collect::<Vec<_>>(),
            vec![
                "operator_review_required",
                "ocr_review_required",
                "canonical_conversion_review_required"
            ]
        );

        for reminder in reminders {
            let imported_document_id = reminder.params["imported_document_id"].as_str();
            let expected_route = format!(
                "/atas/{}?imported_document_id={imported_document_id}&focus=import-review#imported-documents",
                act.id
            );
            assert_eq!(reminder.due_date, "");
            assert_eq!(reminder.severity, "Advisory");
            assert_eq!(reminder.status, "Pending");
            assert_eq!(reminder.source_rule, "imported-document-review-required");
            assert_eq!(
                reminder.source_profile,
                format!("imported-document-review:{imported_document_id}")
            );
            assert_eq!(reminder.params.get("act_id"), Some(&act.id.to_string()));
            assert_eq!(
                reminder.action.as_ref().map(|action| action.kind.as_str()),
                Some("open_imported_document_review")
            );
            assert_eq!(
                reminder
                    .action
                    .as_ref()
                    .and_then(|action| action.route.as_deref()),
                Some(expected_route.as_str())
            );
            assert_eq!(
                reminder.i18n.as_ref().map(|i18n| i18n.title_key.as_str()),
                Some("notifications.reminder.importedDocumentReview.title")
            );

            for forbidden in [
                "sensitive-source-name.pdf",
                "secret-digest-that-must-not-surface",
                "sensitive.importer",
                "sensitive.reviewer",
                "sensitive operator note",
            ] {
                assert!(
                    !reminder.reason.contains(forbidden),
                    "reason leaked {forbidden}"
                );
                assert!(
                    !reminder
                        .params
                        .values()
                        .any(|value| value.contains(forbidden)),
                    "params leaked {forbidden}"
                );
                assert!(
                    !reminder
                        .recommended_next_steps
                        .iter()
                        .any(|value| value.contains(forbidden)),
                    "next steps leaked {forbidden}"
                );
            }
            for forbidden_key in [
                "filename",
                "sha256",
                "digest",
                "imported_by",
                "operator_review_note",
                "operator_reviewed_by",
            ] {
                assert!(!reminder.params.contains_key(forbidden_key));
            }
        }
    }

    #[test]
    fn reminder_numeric_policy_controls_limit_and_day_windows() {
        let fixture = reminder_fixture();

        let policy = WorkflowReminderSettings {
            dashboard_limit: 1,
            ..WorkflowReminderSettings::default()
        };
        let reminders = reminders_for_policy(&fixture, &policy);
        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].source_rule, "csc-art376-annual");

        let policy = WorkflowReminderSettings {
            due_soon_days: 5,
            sources: WorkflowReminderSourceSettings {
                profile_calendar: false,
                act_follow_ups: false,
                attendance_hygiene: true,
                privacy_control_reviews: false,
            },
            ..WorkflowReminderSettings::default()
        };
        let reminders = reminders_for_policy(&fixture, &policy);
        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].source_rule, "act-attendance-missing");
        assert_eq!(reminders[0].status, "Upcoming");

        let policy = WorkflowReminderSettings {
            attendance_lookahead_days: 5,
            ..policy
        };
        assert!(reminders_for_policy(&fixture, &policy).is_empty());
    }

    #[test]
    fn reminder_status_uses_calendar_day_delta_across_year_boundary() {
        assert_eq!(
            reminder_status(date!(2026 - 12 - 20), date!(2027 - 02 - 10), 45),
            "Upcoming"
        );
        assert_eq!(
            reminder_status(date!(2026 - 12 - 20), date!(2027 - 01 - 10), 45),
            "DueSoon"
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
        assert!(reminder.reason.contains("does not claim a legal deadline"));
        assert!(
            reminder
                .reason
                .contains("default Dec 31 fiscal-year end because no fiscal_year_end is recorded")
        );
    }

    #[test]
    fn profile_calendar_supported_preset_exposes_local_coverage_basis() {
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
        let reminder = &reminders[0];
        assert_eq!(reminder.source_rule, "csc-art376-annual");
        assert_eq!(reminder.due_date, "2026-11-30");
        assert_eq!(reminder.status, "Upcoming");
        assert_eq!(
            reminder
                .params
                .get("calendar_preset_support")
                .map(String::as_str),
            Some("supported")
        );
        assert_eq!(
            reminder.params.get("preset_id").map(String::as_str),
            Some("csc-art376-annual")
        );
        assert_eq!(
            reminder.params.get("preset_label").map(String::as_str),
            Some("Assembleia geral anual (CSC art. 376.º)")
        );
        assert_eq!(
            reminder
                .params
                .get("local_due_date_rule_configured")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            reminder
                .params
                .get("local_due_date_calculated")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            reminder
                .params
                .get("months_after_fiscal_year_end")
                .map(String::as_str),
            Some("3")
        );
        assert_eq!(
            reminder.params.get("fiscal_year_end").map(String::as_str),
            Some("08-31")
        );
        assert_eq!(
            reminder.params.get("due_year").map(String::as_str),
            Some("2026")
        );
        assert_eq!(
            reminder.params.get("due_basis").map(String::as_str),
            Some("recorded_fiscal_year_end")
        );
        assert_eq!(
            reminder
                .params
                .get("legal_deadline_calculated")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            reminder.params.get("rule_kind").map(String::as_str),
            Some("commercial_company_annual_general_meeting")
        );
        assert_eq!(
            reminder.params.get("review_status").map(String::as_str),
            Some("pending_source_review")
        );
        assert_eq!(
            reminder.params.get("source_status").map(String::as_str),
            Some("pending_unverified")
        );
        assert_eq!(
            reminder
                .params
                .get("local_advisory_only")
                .map(String::as_str),
            Some("true")
        );
        for key in [
            "legal_deadline_authority_claimed",
            "legal_calendar_authority_claimed",
            "legal_compliance_claimed",
            "external_delivery_claimed",
            "external_calendar_sync_claimed",
            "webhook_delivery_claimed",
            "workflow_completion_claimed",
            "compliance_status_claimed",
            "legal_review_claimed",
            "dre_verification_claimed",
            "provider_effect_claimed",
            "certification_claimed",
        ] {
            assert_eq!(
                reminder.params.get(key).map(String::as_str),
                Some("false"),
                "{key} must remain false for profile-calendar reminders"
            );
        }
        assert_eq!(reminder.law_refs.len(), 1);
        assert_eq!(reminder.law_refs[0].verification, "Pending");
        assert_eq!(reminder.law_refs[0].source_url, None);
        assert!(!reminder.law_refs[0].source_complete);

        let plan = reminder
            .profile_calendar_plan
            .as_ref()
            .expect("profile calendar reminder should expose typed plan");
        assert_eq!(plan.rule_kind, "commercial_company_annual_general_meeting");
        assert_eq!(plan.support_status, "supported");
        assert_eq!(plan.review_status, "pending_source_review");
        assert_eq!(plan.source_status, "pending_unverified");
        assert_eq!(plan.due_rule.kind, "fiscal_year_end_offset");
        assert_eq!(plan.due_rule.months_after_fiscal_year_end, Some(3));
        assert_eq!(
            plan.due_rule.default_fiscal_year_end.as_deref(),
            Some("12-31")
        );
        assert!(plan.evaluation.local_due_date_rule_configured);
        assert!(plan.evaluation.local_due_date_calculated);
        assert!(!plan.evaluation.legal_deadline_calculated);
        assert_eq!(plan.evaluation.fiscal_year_end.as_deref(), Some("08-31"));
        assert_eq!(plan.evaluation.due_year, Some(2026));
        assert_eq!(
            plan.evaluation.due_basis.as_deref(),
            Some("recorded_fiscal_year_end")
        );
        assert!(plan.no_claims.local_advisory_only);
        assert!(!plan.no_claims.legal_deadline_authority_claimed);
        assert!(!plan.no_claims.legal_compliance_claimed);
    }

    #[test]
    fn open_draft_act_missing_attendance_surfaces_work_queue_reminder() {
        let entity = entity_of(EntityKind::SociedadeEmNomeColetivo);
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Open;

        let mut missing = Act::draft(
            book.id,
            "Ata com presencas por completar",
            MeetingChannel::Physical,
        );
        missing.state = ActState::Review;
        missing.meeting_date = Some(date!(2026 - 07 - 20));
        let missing_id = missing.id;
        let missing_id_text = missing_id.to_string();

        let mut complete = Act::draft(
            book.id,
            "Ata com presencas registadas",
            MeetingChannel::Physical,
        );
        complete.state = ActState::Review;
        complete.meeting_date = Some(date!(2026 - 07 - 20));
        complete.attendance_reference = Some("Lista de presencas".to_owned());
        complete.members_present = Some(3);

        let mut signing = Act::draft(book.id, "Ata ja em assinatura", MeetingChannel::Physical);
        signing.state = ActState::Signing;
        signing.meeting_date = Some(date!(2026 - 07 - 20));

        let mut later = Act::draft(book.id, "Ata fora da janela", MeetingChannel::Physical);
        later.meeting_date = Some(date!(2026 - 09 - 30));

        let entities = HashMap::from([(entity.id, entity.clone())]);
        let books = HashMap::from([(book.id, book.clone())]);
        let acts = HashMap::from([
            (missing.id, missing),
            (complete.id, complete),
            (signing.id, signing),
            (later.id, later),
        ]);

        let reminders = dashboard_reminders(
            &entities,
            &books,
            &acts,
            &HashMap::new(),
            date!(2026 - 07 - 09),
        );

        let attendance_reminders = reminders
            .iter()
            .filter(|reminder| reminder.source_rule == "act-attendance-missing")
            .collect::<Vec<_>>();
        assert_eq!(attendance_reminders.len(), 1);

        let reminder = attendance_reminders[0];
        assert_eq!(reminder.due_date, "2026-07-20");
        assert_eq!(reminder.status, "DueSoon");
        assert_eq!(reminder.severity, "Info");
        assert_eq!(reminder.entity_id, entity.id.to_string());
        assert_eq!(reminder.entity_name, entity.name);
        assert_eq!(reminder.source_profile, "csc-commercial");
        assert_eq!(
            reminder.params.get("act_id").map(String::as_str),
            Some(missing_id_text.as_str())
        );
        assert_eq!(
            reminder.params.get("missing_fields").map(String::as_str),
            Some("attendance_reference,presence_counts_or_attendees")
        );
        assert_eq!(
            reminder.params.get("days_until").map(String::as_str),
            Some("11")
        );
        assert_eq!(reminder.law_refs[0].diploma_id, "csc");
        assert_eq!(reminder.law_refs[0].article, "63");

        let expected_route = format!("/atas/{missing_id}");
        assert_eq!(
            reminder
                .action
                .as_ref()
                .map(|action| (action.kind.as_str(), action.route.as_deref())),
            Some(("open_act_attendance", Some(expected_route.as_str())))
        );
        assert_eq!(
            reminder.i18n.as_ref().map(|i18n| i18n.title_key.as_str()),
            Some("notifications.reminder.act.attendance.title")
        );
        assert_eq!(
            reminder
                .i18n
                .as_ref()
                .and_then(|i18n| i18n.action_key.as_deref()),
            Some("notifications.reminder.act.attendance.action")
        );
    }

    #[test]
    fn convocation_notice_missing_meeting_date_surfaces_local_advisory_without_due_date() {
        let mut entity = entity_of(EntityKind::SociedadeAnonima);
        entity.statute = Some(StatuteOverrides {
            convocation_notice_days: Some(10),
            ..StatuteOverrides::default()
        });
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Open;

        let mut act = Act::draft(book.id, "Ata sem data de reuniao", MeetingChannel::Physical);
        act.state = ActState::Review;
        act.attendance_reference = Some("Lista de presencas".to_owned());
        act.members_present = Some(3);
        let act_id = act.id;
        let act_id_text = act_id.to_string();

        let reminders = dashboard_reminders(
            &HashMap::from([(entity.id, entity.clone())]),
            &HashMap::from([(book.id, book)]),
            &HashMap::from([(act.id, act)]),
            &HashMap::new(),
            date!(2026 - 03 - 10),
        );

        let convocation_reminders = reminders
            .iter()
            .filter(|reminder| reminder.source_rule == "act-convening-notice")
            .collect::<Vec<_>>();
        assert_eq!(convocation_reminders.len(), 1);

        let reminder = convocation_reminders[0];
        assert_eq!(reminder.due_date, "");
        assert_eq!(reminder.status, "Pending");
        assert_eq!(reminder.severity, "Warning");
        assert_eq!(reminder.source_profile, "csc-commercial");
        assert_eq!(reminder.law_refs, Vec::<DashboardLawReference>::new());
        assert_eq!(
            reminder.params.get("act_id").map(String::as_str),
            Some(act_id_text.as_str())
        );
        assert_eq!(
            reminder
                .params
                .get("required_notice_days")
                .map(String::as_str),
            Some("10")
        );
        assert_eq!(
            reminder.params.get("meeting_date").map(String::as_str),
            Some("")
        );
        assert_eq!(
            reminder.params.get("notice_due_date").map(String::as_str),
            Some("")
        );
        assert_eq!(
            reminder.params.get("evidence_status").map(String::as_str),
            Some("missing_meeting_date")
        );
        assert_eq!(
            reminder
                .params
                .get("notice_due_date_computable")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            reminder
                .params
                .get("notice_due_date_blocked_by")
                .map(String::as_str),
            Some("missing_meeting_date")
        );
        assert_eq!(
            reminder
                .params
                .get("local_deadline_computed")
                .map(String::as_str),
            Some("false")
        );
        for key in [
            "local_advisory_only",
            "legal_sufficiency_claimed",
            "legal_deadline_computation_claimed",
            "external_delivery_claimed",
            "workflow_completion_claimed",
            "registry_acceptance_claimed",
            "dre_acceptance_claimed",
            "provider_acceptance_claimed",
        ] {
            assert!(
                reminder.params.contains_key(key),
                "{key} no-claim param must be present: {reminder:?}"
            );
        }
        assert_eq!(
            reminder
                .params
                .get("local_advisory_only")
                .map(String::as_str),
            Some("true")
        );
        for key in [
            "legal_sufficiency_claimed",
            "legal_deadline_computation_claimed",
            "external_delivery_claimed",
            "workflow_completion_claimed",
            "registry_acceptance_claimed",
            "dre_acceptance_claimed",
            "provider_acceptance_claimed",
        ] {
            assert_eq!(
                reminder.params.get(key).map(String::as_str),
                Some("false"),
                "{key} must be false"
            );
        }
        assert!(
            reminder.reason.contains("cannot be computed"),
            "reason must explain the missing meeting-date block: {reminder:?}"
        );
        assert!(
            reminder.reason.contains("no legal deadline computation"),
            "reason must avoid deadline-computation claims: {reminder:?}"
        );
        assert!(
            reminder.reason.contains("registry/DRE acceptance"),
            "reason must avoid registry/DRE acceptance claims: {reminder:?}"
        );
        assert!(
            reminder.reason.contains("provider acceptance"),
            "reason must avoid provider acceptance claims: {reminder:?}"
        );
        assert_eq!(
            reminder
                .action
                .as_ref()
                .map(|action| (action.kind.as_str(), action.route.as_deref())),
            Some((
                "open_act_convening_notice",
                Some(format!("/atas/{act_id}").as_str())
            ))
        );
        assert_eq!(
            reminder.i18n.as_ref().map(|i18n| i18n.title_key.as_str()),
            Some("notifications.reminder.act.conveningNotice.title")
        );
        assert_eq!(
            reminder.i18n.as_ref().map(|i18n| i18n.body_key.as_str()),
            Some("notifications.reminder.act.conveningNotice.missingMeetingDate.body")
        );
        assert!(
            reminder
                .recommended_next_steps
                .iter()
                .any(|step| step.contains("Record the meeting date")),
            "missing-date reminder should point to the next metadata step: {reminder:?}"
        );
    }

    #[test]
    fn convocation_notice_missing_evidence_surfaces_local_advisory_reminder() {
        let mut entity = entity_of(EntityKind::SociedadeAnonima);
        entity.statute = Some(StatuteOverrides {
            convocation_notice_days: Some(10),
            ..StatuteOverrides::default()
        });
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Open;

        let mut act = Act::draft(
            book.id,
            "Ata com convocatoria por rever",
            MeetingChannel::Physical,
        );
        act.state = ActState::Review;
        act.meeting_date = Some(date!(2026 - 03 - 30));
        act.attendance_reference = Some("Lista de presencas".to_owned());
        act.members_present = Some(3);
        let act_id = act.id;
        let act_id_text = act_id.to_string();

        let reminders = dashboard_reminders(
            &HashMap::from([(entity.id, entity.clone())]),
            &HashMap::from([(book.id, book)]),
            &HashMap::from([(act.id, act)]),
            &HashMap::new(),
            date!(2026 - 03 - 10),
        );

        let convocation_reminders = reminders
            .iter()
            .filter(|reminder| reminder.source_rule == "act-convening-notice")
            .collect::<Vec<_>>();
        assert_eq!(convocation_reminders.len(), 1);

        let reminder = convocation_reminders[0];
        assert_eq!(reminder.due_date, "2026-03-20");
        assert_eq!(reminder.status, "DueSoon");
        assert_eq!(reminder.severity, "Warning");
        assert_eq!(reminder.source_profile, "csc-commercial");
        assert_eq!(reminder.law_refs, Vec::<DashboardLawReference>::new());
        assert_eq!(
            reminder.params.get("act_id").map(String::as_str),
            Some(act_id_text.as_str())
        );
        assert_eq!(
            reminder
                .params
                .get("required_notice_days")
                .map(String::as_str),
            Some("10")
        );
        assert_eq!(
            reminder.params.get("meeting_date").map(String::as_str),
            Some("2026-03-30")
        );
        assert_eq!(
            reminder.params.get("notice_due_date").map(String::as_str),
            Some("2026-03-20")
        );
        assert_eq!(
            reminder.params.get("dispatch_date").map(String::as_str),
            Some("")
        );
        assert_eq!(
            reminder.params.get("antecedence_days").map(String::as_str),
            Some("")
        );
        assert_eq!(
            reminder.params.get("evidence_status").map(String::as_str),
            Some("missing_or_unverifiable_dispatch_evidence")
        );
        for key in [
            "local_advisory_only",
            "legal_sufficiency_claimed",
            "external_delivery_claimed",
            "workflow_completion_claimed",
        ] {
            assert!(
                reminder.params.contains_key(key),
                "{key} no-claim param must be present: {reminder:?}"
            );
        }
        assert_eq!(
            reminder
                .params
                .get("local_advisory_only")
                .map(String::as_str),
            Some("true")
        );
        for key in [
            "legal_sufficiency_claimed",
            "external_delivery_claimed",
            "workflow_completion_claimed",
        ] {
            assert_eq!(
                reminder.params.get(key).map(String::as_str),
                Some("false"),
                "{key} must be false"
            );
        }
        assert!(
            reminder.reason.contains("local advisory"),
            "reason must stay local/advisory: {reminder:?}"
        );
        assert!(
            reminder.reason.contains("no legal sufficiency"),
            "reason must avoid legal-sufficiency claims: {reminder:?}"
        );
        assert_eq!(
            reminder
                .action
                .as_ref()
                .map(|action| (action.kind.as_str(), action.route.as_deref())),
            Some((
                "open_act_convening_notice",
                Some(format!("/atas/{act_id}").as_str())
            ))
        );
        assert_eq!(
            reminder.i18n.as_ref().map(|i18n| i18n.title_key.as_str()),
            Some("notifications.reminder.act.conveningNotice.title")
        );
    }

    #[test]
    fn convocation_notice_short_evidence_surfaces_local_advisory_reminder() {
        let mut entity = entity_of(EntityKind::SociedadeAnonima);
        entity.statute = Some(StatuteOverrides {
            convocation_notice_days: Some(10),
            ..StatuteOverrides::default()
        });
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Open;

        let mut act = Act::draft(
            book.id,
            "Ata com antecedencia curta",
            MeetingChannel::Physical,
        );
        act.state = ActState::Review;
        act.meeting_date = Some(date!(2026 - 03 - 30));
        act.attendance_reference = Some("Lista de presencas".to_owned());
        act.members_present = Some(3);
        act.convening = Some(Convening {
            dispatch_date: Some(date!(2026 - 03 - 25)),
            ..Convening::default()
        });

        let reminders = dashboard_reminders(
            &HashMap::from([(entity.id, entity.clone())]),
            &HashMap::from([(book.id, book)]),
            &HashMap::from([(act.id, act)]),
            &HashMap::new(),
            date!(2026 - 03 - 10),
        );

        let reminder = reminders
            .iter()
            .find(|reminder| reminder.source_rule == "act-convening-notice")
            .unwrap_or_else(|| panic!("missing short notice reminder: {reminders:?}"));
        assert_eq!(reminder.due_date, "2026-03-20");
        assert_eq!(
            reminder.params.get("dispatch_date").map(String::as_str),
            Some("2026-03-25")
        );
        assert_eq!(
            reminder.params.get("antecedence_days").map(String::as_str),
            Some("5")
        );
        assert_eq!(
            reminder.params.get("evidence_status").map(String::as_str),
            Some("short_dispatch_evidence")
        );
        assert!(
            reminder
                .reason
                .contains("external delivery, or workflow completion is claimed")
        );
    }

    #[test]
    fn convocation_notice_sufficient_evidence_is_suppressed() {
        let mut entity = entity_of(EntityKind::SociedadeAnonima);
        entity.statute = Some(StatuteOverrides {
            convocation_notice_days: Some(10),
            ..StatuteOverrides::default()
        });
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Open;

        let mut act = Act::draft(
            book.id,
            "Ata com convocatoria suficiente",
            MeetingChannel::Physical,
        );
        act.state = ActState::Review;
        act.meeting_date = Some(date!(2026 - 03 - 30));
        act.attendance_reference = Some("Lista de presencas".to_owned());
        act.members_present = Some(3);
        act.convening = Some(Convening {
            dispatch_date: Some(date!(2026 - 03 - 15)),
            ..Convening::default()
        });

        let reminders = dashboard_reminders(
            &HashMap::from([(entity.id, entity)]),
            &HashMap::from([(book.id, book)]),
            &HashMap::from([(act.id, act)]),
            &HashMap::new(),
            date!(2026 - 03 - 10),
        );
        assert!(
            reminders
                .iter()
                .all(|reminder| reminder.source_rule != "act-convening-notice"),
            "sufficient dispatch evidence should suppress the reminder: {reminders:?}"
        );
    }

    #[test]
    fn open_follow_ups_surface_as_act_routed_reminders_without_mutating_sealed_act() {
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let book = Book::new(entity.id, BookKind::AssembleiaGeral);
        let mut act = Act::draft(
            book.id,
            "Ata de aprovação de contas",
            MeetingChannel::Physical,
        );
        act.state = ActState::Sealed;
        let act_id = act.id;
        let created_at = OffsetDateTime::UNIX_EPOCH;

        let open = StoredFollowUp {
            id: "follow-up-open".to_owned(),
            act_id,
            agenda_number: Some(2),
            deliberation_index: Some(0),
            title: "Enviar certidão ao contabilista".to_owned(),
            detail: Some("Confirmar envio depois da assinatura externa.".to_owned()),
            due_date: Some(date!(2026 - 07 - 01)),
            assignee: Some("ana".to_owned()),
            assignee_display: Some("Ana Silva".to_owned()),
            status: StoredFollowUpStatus::Open,
            created_at,
            created_by: "operator".to_owned(),
            completed_at: None,
            completed_by: None,
        };
        let completed = StoredFollowUp {
            id: "follow-up-completed".to_owned(),
            status: StoredFollowUpStatus::Completed,
            completed_at: Some(created_at),
            completed_by: Some("operator".to_owned()),
            ..open.clone()
        };
        let entities = HashMap::from([(entity.id, entity.clone())]);
        let books = HashMap::from([(book.id, book.clone())]);
        let acts = HashMap::from([(act.id, act)]);
        let follow_ups = HashMap::from([
            (open.id.clone(), open.clone()),
            (completed.id.clone(), completed),
        ]);

        let reminders = dashboard_reminders_with_follow_ups(
            &entities,
            &books,
            &acts,
            &follow_ups,
            &HashMap::new(),
            date!(2026 - 07 - 09),
            &WorkflowReminderSettings::default(),
        );

        let follow_up_reminders = reminders
            .iter()
            .filter(|reminder| reminder.source_rule == "act-follow-up")
            .collect::<Vec<_>>();
        assert_eq!(follow_up_reminders.len(), 1);
        let reminder = follow_up_reminders[0];
        assert_eq!(reminder.due_date, "2026-07-01");
        assert_eq!(reminder.status, "Overdue");
        assert_eq!(reminder.severity, "Warning");
        assert_eq!(reminder.entity_id, entity.id.to_string());
        assert_eq!(reminder.entity_name, entity.name);
        assert_eq!(reminder.source_profile, "follow-up:follow-up-open");
        assert_eq!(
            reminder.params.get("follow_up_title").map(String::as_str),
            Some("Enviar certidão ao contabilista")
        );
        assert_eq!(
            reminder.params.get("act_title").map(String::as_str),
            Some("Ata de aprovação de contas")
        );
        assert_eq!(
            reminder.params.get("assignee_display").map(String::as_str),
            Some("Ana Silva")
        );
        let expected_route = format!("/atas/{act_id}");
        assert_eq!(
            reminder
                .action
                .as_ref()
                .map(|action| (action.kind.as_str(), action.route.as_deref())),
            Some(("open_act_follow_up", Some(expected_route.as_str())))
        );
        assert_eq!(
            reminder.i18n.as_ref().map(|i18n| i18n.title_key.as_str()),
            Some("notifications.reminder.followUp.title")
        );
        assert_eq!(
            acts.get(&act_id).map(|sealed| sealed.state),
            Some(ActState::Sealed)
        );
    }

    #[test]
    fn reminder_generated_absent_owner_dispatch_evidence_required_pending_routes_to_act_document_workflow()
     {
        let reminders = reminders_for_generated_dispatch_evidence(&[]);

        let absent_owner_reminders = reminders
            .iter()
            .filter(|reminder| reminder.source_rule == "absent-owner-dispatch-evidence")
            .collect::<Vec<_>>();
        assert_eq!(absent_owner_reminders.len(), 1);
        let reminder = absent_owner_reminders[0];
        let expected_route = format!(
            "/atas/{}",
            reminder.params.get("act_id").expect("act_id param")
        );
        assert_eq!(reminder.source_rule, "absent-owner-dispatch-evidence");
        assert_eq!(
            reminder.source_profile,
            "condominium-generated-communication"
        );
        assert_eq!(reminder.due_date, "");
        assert_eq!(reminder.status, "Pending");
        assert_eq!(reminder.severity, "Advisory");
        assert_eq!(
            reminder
                .params
                .get("dispatch_evidence_status")
                .map(String::as_str),
            Some("required_pending")
        );
        assert_eq!(
            reminder
                .params
                .get("required_recipient_count")
                .map(String::as_str),
            Some("2")
        );
        assert_eq!(
            reminder
                .params
                .get("recorded_recipient_count")
                .map(String::as_str),
            Some("0")
        );
        assert_eq!(
            reminder
                .params
                .get("missing_recipients")
                .map(String::as_str),
            Some("Fração B, Fração C")
        );
        assert_eq!(
            reminder.params.get("template_id").map(String::as_str),
            Some(crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID)
        );
        assert_eq!(
            reminder
                .action
                .as_ref()
                .map(|action| (action.kind.as_str(), action.route.as_deref())),
            Some((
                "open_absent_owner_dispatch_evidence",
                Some(expected_route.as_str())
            ))
        );
        assert_eq!(
            reminder
                .action
                .as_ref()
                .and_then(|action| action.api_href.as_deref()),
            Some("/v1/documents/generated/generated-absent-owner-1/dispatch-evidence")
        );
        assert_eq!(
            reminder.i18n.as_ref().map(|i18n| i18n.title_key.as_str()),
            Some("notifications.reminder.absentOwnerDispatch.title")
        );
        assert!(
            reminder
                .reason
                .contains("does not claim sending, delivery, legal notice completion")
        );
    }

    #[test]
    fn reminder_generated_absent_owner_dispatch_evidence_partial_routes_to_act_document_workflow() {
        let reminders = reminders_for_generated_dispatch_evidence(&["Fração B"]);

        let absent_owner_reminders = reminders
            .iter()
            .filter(|reminder| reminder.source_rule == "absent-owner-dispatch-evidence")
            .collect::<Vec<_>>();
        assert_eq!(absent_owner_reminders.len(), 1);
        let reminder = absent_owner_reminders[0];
        let expected_route = format!(
            "/atas/{}",
            reminder.params.get("act_id").expect("act_id param")
        );
        assert_eq!(
            reminder
                .params
                .get("dispatch_evidence_status")
                .map(String::as_str),
            Some("operator_evidence_partial")
        );
        assert_eq!(
            reminder
                .params
                .get("recorded_recipient_count")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            reminder
                .params
                .get("missing_recipient_count")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            reminder
                .params
                .get("recorded_recipients")
                .map(String::as_str),
            Some("Fração B")
        );
        assert_eq!(
            reminder
                .params
                .get("missing_recipients")
                .map(String::as_str),
            Some("Fração C")
        );
        assert_eq!(
            reminder
                .action
                .as_ref()
                .and_then(|action| action.route.as_deref()),
            Some(expected_route.as_str())
        );
    }

    #[test]
    fn reminder_generated_absent_owner_dispatch_evidence_covered_is_suppressed() {
        let reminders = reminders_for_generated_dispatch_evidence(&["Fração B", "Fração C"]);

        assert!(
            reminders
                .iter()
                .all(|reminder| reminder.source_rule != "absent-owner-dispatch-evidence")
        );
    }

    #[test]
    fn reminder_generated_absent_owner_no_due_date_does_not_evict_earliest_dated_reminder() {
        let mut fixture = reminder_fixture();
        let (entities, books, acts, generated_dispatch_evidence) =
            sealed_condominium_dispatch_fixture(&[]);
        fixture.entities.extend(entities);
        fixture.books.extend(books);
        fixture.acts.extend(acts);
        let policy = WorkflowReminderSettings {
            dashboard_limit: 1,
            ..WorkflowReminderSettings::default()
        };

        let reminders = dashboard_reminders_with_generated_dispatch_evidence(
            ReminderInputs {
                entities: &fixture.entities,
                books: &fixture.books,
                acts: &fixture.acts,
                follow_ups: &fixture.follow_ups,
                generated_dispatch_evidence: &generated_dispatch_evidence,
                imported_documents: &[],
                registry_extracts: &fixture.registry_extracts,
                breach_playbooks: &HashMap::new(),
                transfer_controls: &HashMap::new(),
            },
            date!(2026 - 07 - 09),
            &policy,
        );

        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].source_rule, "condominio-annual");
        assert_eq!(reminders[0].due_date, "2026-01-15");
        assert_eq!(reminders[0].status, "Overdue");
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
    fn custom_fiscal_year_first_year_suppresses_before_and_at_first_year_end() {
        let mut entity = entity_of(EntityKind::SociedadeAnonima);
        entity.fiscal_year_end = Some("08-31".to_owned());
        let entities = HashMap::from([(entity.id, entity.clone())]);
        let registry_extracts = HashMap::from([(
            entity.id,
            registry_extract_with_constitution_date("2026-01-10"),
        )]);

        for today in [date!(2026 - 07 - 09), date!(2026 - 08 - 31)] {
            let reminders = dashboard_reminders(
                &entities,
                &HashMap::new(),
                &HashMap::new(),
                &registry_extracts,
                today,
            );

            assert!(
                reminders
                    .iter()
                    .all(|reminder| reminder.source_rule != "csc-art376-annual"),
                "dashboard must not report annual accounts while the company is in its first fiscal year"
            );
        }
    }

    #[test]
    fn custom_fiscal_year_after_first_year_end_emits_first_due_reminder() {
        let mut entity = entity_of(EntityKind::SociedadeAnonima);
        entity.fiscal_year_end = Some("08-31".to_owned());
        let entities = HashMap::from([(entity.id, entity.clone())]);
        let registry_extracts = HashMap::from([(
            entity.id,
            registry_extract_with_constitution_date("2026-01-10"),
        )]);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &registry_extracts,
            date!(2026 - 09 - 01),
        );

        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].source_rule, "csc-art376-annual");
        assert_eq!(reminders[0].due_date, "2026-11-30");
        assert_eq!(reminders[0].entity_id, entity.id.to_string());
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
    fn condominium_profile_calendar_surfaces_fixed_annual_date_advisory() {
        let entity = entity_of(EntityKind::Condominio);
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity.clone());

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2026 - 01 - 15),
        );

        assert_eq!(reminders.len(), 1);
        let reminder = &reminders[0];
        assert_eq!(reminder.source_rule, "condominio-annual");
        assert_eq!(reminder.source_profile, "condominio-dl268");
        assert_eq!(reminder.entity_id, entity.id.to_string());
        assert_eq!(reminder.due_date, "2026-01-15");
        assert_eq!(reminder.status, "DueSoon");
        assert_eq!(reminder.severity, "Advisory");
        assert_eq!(reminder.law_refs.len(), 1);
        assert_eq!(reminder.law_refs[0].diploma_id, "cc");
        assert_eq!(reminder.law_refs[0].article, "1431");
        assert_eq!(reminder.law_refs[0].verification, "Pending");
        assert_eq!(reminder.law_refs[0].source_url, None);
        assert!(!reminder.law_refs[0].source_complete);
        assert_eq!(
            reminder
                .params
                .get("calendar_preset_support")
                .map(String::as_str),
            Some("supported")
        );
        assert_eq!(
            reminder.params.get("preset_id").map(String::as_str),
            Some("condominio-annual")
        );
        assert_eq!(
            reminder.params.get("preset_label").map(String::as_str),
            Some("Assembleia ordinária anual de condóminos (DL 268/94)")
        );
        assert_eq!(
            reminder
                .params
                .get("local_due_date_rule_configured")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            reminder
                .params
                .get("legal_deadline_calculated")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            reminder
                .params
                .get("local_due_date_calculated")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            reminder
                .params
                .get("annual_fixed_month")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            reminder.params.get("annual_fixed_day").map(String::as_str),
            Some("15")
        );
        assert_eq!(
            reminder.params.get("due_year").map(String::as_str),
            Some("2026")
        );
        assert_eq!(
            reminder.params.get("due_basis").map(String::as_str),
            Some("annual_fixed_date")
        );
        assert_eq!(
            reminder.params.get("rule_kind").map(String::as_str),
            Some("condominium_annual_assembly")
        );
        assert_eq!(
            reminder.params.get("review_status").map(String::as_str),
            Some("pending_source_review")
        );
        assert_eq!(
            reminder.params.get("source_status").map(String::as_str),
            Some("pending_unverified")
        );
        assert!(
            !reminder.params.contains_key("months_after_fiscal_year_end"),
            "fixed-date condominium presets must not pretend to use a fiscal-year offset"
        );
        assert!(
            !reminder.params.contains_key("fiscal_year_end"),
            "fixed-date condominium presets must not invent a fiscal-year basis"
        );
        assert!(
            !reminder.params.contains_key("unsupported_reason"),
            "supported fixed-date condominium presets must not report an unsupported reason"
        );
        for key in [
            "legal_deadline_authority_claimed",
            "legal_calendar_authority_claimed",
            "legal_compliance_claimed",
            "external_delivery_claimed",
            "external_calendar_sync_claimed",
            "webhook_delivery_claimed",
            "workflow_completion_claimed",
            "compliance_status_claimed",
            "legal_review_claimed",
            "dre_verification_claimed",
            "provider_effect_claimed",
            "certification_claimed",
        ] {
            assert_eq!(
                reminder.params.get(key).map(String::as_str),
                Some("false"),
                "{key} must remain false for condominium profile-calendar reminders"
            );
        }
        let plan = reminder
            .profile_calendar_plan
            .as_ref()
            .expect("condominium profile calendar reminder should expose typed plan");
        assert_eq!(plan.rule_kind, "condominium_annual_assembly");
        assert_eq!(plan.support_status, "supported");
        assert_eq!(plan.review_status, "pending_source_review");
        assert_eq!(plan.source_status, "pending_unverified");
        assert_eq!(plan.due_rule.kind, "annual_fixed_date");
        assert_eq!(plan.due_rule.months_after_fiscal_year_end, None);
        assert_eq!(plan.due_rule.default_fiscal_year_end, None);
        assert_eq!(plan.due_rule.annual_fixed_month, Some(1));
        assert_eq!(plan.due_rule.annual_fixed_day, Some(15));
        assert_eq!(plan.due_rule.unsupported_reason, None);
        assert!(plan.evaluation.local_due_date_rule_configured);
        assert!(plan.evaluation.local_due_date_calculated);
        assert!(!plan.evaluation.legal_deadline_calculated);
        assert_eq!(plan.evaluation.fiscal_year_end, None);
        assert_eq!(plan.evaluation.due_year, Some(2026));
        assert_eq!(
            plan.evaluation.due_basis.as_deref(),
            Some("annual_fixed_date")
        );
        assert_eq!(plan.evaluation.unsupported_reason, None);
        assert!(!plan.no_claims.external_delivery_claimed);
        assert!(
            reminder
                .reason
                .contains("using the local fixed annual advisory date")
        );
        assert!(
            reminder
                .reason
                .contains("profile-specific exceptions remain manual context")
        );
        assert!(
            reminder.reason.contains("does not claim a legal deadline"),
            "condominium profile-calendar copy must keep the no-legal-claim boundary"
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
    fn profile_calendar_leap_day_fiscal_year_end_is_clamped_through_dashboard() {
        let mut entity = entity_of(EntityKind::SociedadePorQuotas);
        entity.fiscal_year_end = Some("02-29".to_owned());
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity);

        let reminders = dashboard_reminders(
            &entities,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            date!(2025 - 01 - 15),
        );

        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].due_date, "2025-05-28");
        assert_eq!(
            reminders[0]
                .params
                .get("fiscal_year_end")
                .map(String::as_str),
            Some("02-29")
        );
        assert_eq!(
            reminders[0]
                .profile_calendar_plan
                .as_ref()
                .and_then(|plan| plan.evaluation.fiscal_year_end.as_deref()),
            Some("02-29")
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
