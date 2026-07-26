//! Deterministic search-corpus construction shared by the API and external projector.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use chancela_action_center::{
    BackupRecoveryFreshnessReview, BackupRecoveryFreshnessStatus, DashboardSearchActionable,
    GeneratedDispatchEvidenceSnapshot, ReminderInputs, backup_recovery_freshness_alert,
    dashboard_alerts, dashboard_reminders_with_generated_dispatch_evidence,
    search_actionables_from_rows, sort_dashboard_alerts,
};
use chancela_core::{
    Act, ActId, Book, BookId, Entity, EntityId, GroupTemplateLibrary, GroupTemplateLibraryRevision,
    TemplateLibraryId,
};
use chancela_search::{SearchDocument, SearchDocumentContent, SearchKind, SearchSettings};
use chancela_store::{
    Store, StoredDocument, StoredDocumentSearchMetadata, StoredFollowUp,
    StoredGeneratedDocumentDispatchEvidence, StoredImportedDocumentMeta,
    StoredImportedDocumentReviewHistoryEntry, StoredPaperBookImportMeta, StoredPaperBookOcrDraft,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

const REDACTED: &str = "<redacted>";

#[derive(Default)]
pub struct DurableCorpusRows {
    pub imported_documents: Vec<StoredImportedDocumentMeta>,
    pub imported_review_history: HashMap<String, Vec<StoredImportedDocumentReviewHistoryEntry>>,
    pub paper_imports: Vec<(StoredPaperBookImportMeta, Vec<StoredPaperBookOcrDraft>)>,
    pub generated_documents: Vec<StoredDocumentSearchMetadata>,
    pub user_templates: Vec<(String, String)>,
}

pub struct ProjectionInputs {
    pub entities: HashMap<EntityId, Entity>,
    pub books: HashMap<BookId, Book>,
    pub acts: HashMap<ActId, Act>,
    pub follow_ups: HashMap<String, StoredFollowUp>,
    pub template_libraries: HashMap<TemplateLibraryId, GroupTemplateLibrary>,
    pub template_revisions:
        HashMap<(chancela_core::GroupId, TemplateLibraryId, u64), GroupTemplateLibraryRevision>,
    pub events: Vec<chancela_ledger::Event>,
    pub durable: DurableCorpusRows,
    pub actionables: Vec<DashboardSearchActionable>,
}

#[derive(Debug)]
pub struct ProjectionBuild {
    pub documents: Vec<SearchDocument>,
    pub last_event_seq: Option<u64>,
    pub indexed_content_chars: u64,
    pub content_budget_exhausted: bool,
    pub projection_utc_date: time::Date,
}

struct CorpusContentBudget {
    remaining: usize,
    retained: u64,
    exhausted: bool,
}

impl CorpusContentBudget {
    fn new(max_chars: u64) -> Self {
        Self {
            remaining: usize::try_from(max_chars).unwrap_or(usize::MAX),
            retained: 0,
            exhausted: false,
        }
    }

    fn apply(&mut self, mut document: SearchDocument) -> SearchDocument {
        self.apply_body(&mut document.body, &mut document.content_truncated);
        if let Some(privileged) = &mut document.privileged {
            self.apply_body(&mut privileged.body, &mut privileged.content_truncated);
        }
        document
    }

    fn apply_body(&mut self, body: &mut String, truncated: &mut bool) {
        let body_chars = body.chars().count();
        if body_chars > self.remaining {
            *body = body.chars().take(self.remaining).collect();
            *truncated = true;
            self.retained = self.retained.saturating_add(self.remaining as u64);
            self.remaining = 0;
            self.exhausted = true;
        } else {
            self.remaining -= body_chars;
            self.retained = self.retained.saturating_add(body_chars as u64);
        }
    }
}

fn apply_global_content_budget(
    mut documents: Vec<SearchDocument>,
    max_chars: u64,
) -> (Vec<SearchDocument>, u64, bool) {
    documents.sort_by(|left, right| left.id.cmp(&right.id));
    let mut budget = CorpusContentBudget::new(max_chars);
    let documents = documents
        .into_iter()
        .map(|document| budget.apply(document))
        .collect();
    (documents, budget.retained, budget.exhausted)
}

#[derive(Clone, Default)]
struct Relation {
    tenant_id: Option<String>,
    entity_id: Option<String>,
    entity_name: Option<String>,
    book_id: Option<String>,
    book_label: Option<String>,
    act_id: Option<String>,
}

fn ensure_projection_active(shutdown: &AtomicBool) -> Result<(), String> {
    if shutdown.load(Ordering::Acquire) {
        Err("search projection cancelled for shutdown".to_owned())
    } else {
        Ok(())
    }
}

fn bounded_projector_diagnostic(raw: &str) -> Option<String> {
    let mut value = String::with_capacity(raw.len().min(512));
    for character in raw.trim().chars().take(512) {
        value.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    (!value.is_empty()).then_some(value)
}

fn bounded_projection_error(context: &str, error: impl std::fmt::Display) -> String {
    let detail = bounded_projector_diagnostic(&error.to_string())
        .unwrap_or_else(|| "unknown validation failure".to_owned());
    format!("{context}: {detail}")
}

fn guest_entity_value(entity: &Entity) -> Value {
    let profile = chancela_core::profile_for(entity.kind);
    serde_json::json!({
        "id": entity.id.to_string(),
        "tenant_id": entity.tenant_id.to_string(),
        "group_id": entity.group_id.map(|id| id.to_string()),
        "name": entity.name,
        "nipc": REDACTED,
        "nipc_validated": false,
        "seat": REDACTED,
        "family": entity.family,
        "kind": entity.kind,
        "fiscal_year_end": entity.fiscal_year_end,
        "profile": {
            "family": profile.family,
            "rule_pack_id": profile.rule_pack_id,
            "allowed_channels": profile.allowed_channels,
            "signature_policy": profile.signature_policy,
            "template_family": profile.template_family,
            "calendar_presets": profile.calendar_presets.iter().map(|preset| serde_json::json!({
                "id": preset.id,
                "label": preset.label,
                "months_after_fiscal_year_end": preset.months_after_fiscal_year_end,
            })).collect::<Vec<_>>(),
            "attendee_qualities": profile.attendee_qualities,
        },
        "statute": entity.statute,
        "document_layout_override": entity.document_layout_override,
    })
}

fn guest_book_value(book: &Book) -> Value {
    let opening = book.termo_abertura.as_ref();
    let closing = book.termo_encerramento.as_ref();
    serde_json::json!({
        "id": book.id.to_string(),
        "entity_id": book.entity_id.to_string(),
        "kind": book.kind,
        "state": book.state,
        "purpose": Value::Null,
        "numbering_scheme": opening.map(|value| value.numbering_scheme),
        "opening_date": opening.map(|value| value.opening_date.to_string()),
        "closing_date": closing.map(|value| value.closing_date.to_string()),
        "closing_reason": closing.map(|value| &value.reason),
        "last_ata_number": book.last_ata_number,
        "predecessor": Value::Null,
        "required_signatories_abertura": opening.map(|value| {
            vec![REDACTED.to_owned(); value.required_signatories.len()]
        }),
        "required_signatories_encerramento": closing.map(|value| {
            vec![REDACTED.to_owned(); value.required_signatories.len()]
        }),
        "required_signatory_records_abertura": opening.map(|value| {
            guest_termo_signatories(
                &value.required_signatory_records,
                value.required_signatories.len(),
            )
        }),
        "required_signatory_records_encerramento": closing.map(|value| {
            guest_termo_signatories(
                &value.required_signatory_records,
                value.required_signatories.len(),
            )
        }),
        "page_capacity": book.page_capacity,
        "pages_used": book.pages_used,
        "pages_reserved": book.pages_reserved,
        "remaining_pages": book.pages_remaining(),
        "capacity_exhausted": book.is_capacity_exhausted(),
        "document_layout_override": book.document_layout_override,
    })
}

fn guest_termo_signatories(
    records: &[chancela_core::TermoSignatory],
    legacy_count: usize,
) -> Vec<Value> {
    let count = if records.is_empty() {
        legacy_count
    } else {
        records.len()
    };
    (0..count)
        .map(|_| {
            serde_json::json!({
                "name": REDACTED,
                "capacity": Value::Null,
                "capacity_note": Value::Null,
                "email": Value::Null,
            })
        })
        .collect()
}

fn guest_act_value(act: &Act) -> Value {
    let mut value = serde_json::to_value(act).unwrap_or(Value::Null);
    let Value::Object(fields) = &mut value else {
        return value;
    };
    fields.remove("page_count");
    fields.remove("superseded_signing_snapshots");
    fields.insert("title".to_owned(), Value::String(REDACTED.to_owned()));
    if !fields.get("place").is_none_or(Value::is_null) {
        fields.insert("place".to_owned(), Value::String(REDACTED.to_owned()));
    }
    for key in [
        "mesa",
        "agenda",
        "attendance_reference",
        "referenced_documents",
        "written_resolution_evidence",
        "deliberations",
        "deliberation_items",
        "telematic_evidence",
        "attachments",
        "signatories",
        "seal_metadata",
        "convening",
        "convening_waiver",
        "attendees",
        "ai_provenance",
    ] {
        if let Some(field) = fields.get_mut(key) {
            redact_projection_strings(field);
        }
    }
    if let Some(Value::Object(body)) = fields.get_mut("body")
        && let Some(source) = body.get_mut("source")
    {
        *source = Value::String(REDACTED.to_owned());
    }
    if let Some(date) = act.meeting_date {
        fields.insert("meeting_date".to_owned(), Value::String(date.to_string()));
    }
    if let Some(meeting_time) = act.meeting_time {
        fields.insert(
            "meeting_time".to_owned(),
            Value::String(format!(
                "{:02}:{:02}",
                meeting_time.hour(),
                meeting_time.minute()
            )),
        );
    }
    fields.insert(
        "payload_digest".to_owned(),
        act.payload_digest
            .as_ref()
            .map(|digest| Value::String(digest_hex(digest)))
            .unwrap_or(Value::Null),
    );
    value
}

fn redact_projection_strings(value: &mut Value) {
    match value {
        Value::String(text) => *text = REDACTED.to_owned(),
        Value::Array(items) => {
            for item in items {
                redact_projection_strings(item);
            }
        }
        Value::Object(fields) => {
            for value in fields.values_mut() {
                redact_projection_strings(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

pub fn build_corpus(
    inputs: ProjectionInputs,
    settings: &SearchSettings,
    shutdown: &AtomicBool,
    projection_as_of: OffsetDateTime,
) -> Result<ProjectionBuild, String> {
    ensure_projection_active(shutdown)?;
    let default_template_registry = chancela_templates::load_registry()
        .map_err(|error| bounded_projection_error("default template registry is invalid", error))?;
    let ProjectionInputs {
        entities,
        books,
        acts,
        follow_ups,
        template_libraries,
        template_revisions,
        events,
        durable,
        actionables,
    } = inputs;
    let projection_as_of = projection_as_of.to_offset(UtcOffset::UTC);
    let mut entity_relations = HashMap::new();
    for entity in entities.values() {
        ensure_projection_active(shutdown)?;
        entity_relations.insert(
            entity.id.to_string(),
            Relation {
                tenant_id: Some(entity.tenant_id.to_string()),
                entity_id: Some(entity.id.to_string()),
                entity_name: Some(entity.name.clone()),
                ..Relation::default()
            },
        );
    }
    let mut book_relations = HashMap::new();
    let mut privileged_book_relations = HashMap::new();
    for book in books.values() {
        ensure_projection_active(shutdown)?;
        let mut relation = entity_relations
            .get(&book.entity_id.to_string())
            .cloned()
            .unwrap_or_default();
        relation.book_id = Some(book.id.to_string());
        relation.book_label = Some(book_label(book));
        book_relations.insert(book.id.to_string(), relation.clone());
        relation.book_label = Some(privileged_book_label(book));
        privileged_book_relations.insert(book.id.to_string(), relation);
    }
    let mut act_relations = HashMap::new();
    let mut privileged_act_relations = HashMap::new();
    for act in acts.values() {
        ensure_projection_active(shutdown)?;
        let mut relation = book_relations
            .get(&act.book_id.to_string())
            .cloned()
            .unwrap_or_default();
        relation.act_id = Some(act.id.to_string());
        act_relations.insert(act.id.to_string(), relation);
        let mut privileged_relation = privileged_book_relations
            .get(&act.book_id.to_string())
            .cloned()
            .unwrap_or_default();
        privileged_relation.act_id = Some(act.id.to_string());
        privileged_act_relations.insert(act.id.to_string(), privileged_relation);
    }

    let mut documents = Vec::with_capacity(
        entities.len()
            + books.len()
            + acts.len()
            + follow_ups.len()
            + events.len().saturating_mul(2),
    );
    let mut ordered_entities: Vec<_> = entities.values().collect();
    ordered_entities.sort_by_key(|entity| entity.id.0);
    let mut ordered_books: Vec<_> = books.values().collect();
    ordered_books.sort_by_key(|book| book.id.0);
    let mut ordered_acts: Vec<_> = acts.values().collect();
    ordered_acts.sort_by_key(|act| act.id.0);
    let mut ordered_follow_ups: Vec<_> = follow_ups.values().collect();
    ordered_follow_ups.sort_by(|left, right| left.id.cmp(&right.id));
    let mut ordered_libraries: Vec<_> = template_libraries.values().collect();
    ordered_libraries.sort_by_key(|library| library.id);
    let mut ordered_revisions: Vec<_> = template_revisions.values().collect();
    ordered_revisions.sort_by_key(|revision| (revision.library_id, revision.revision));

    for entity in ordered_entities {
        ensure_projection_active(shutdown)?;
        let public_view = guest_entity_value(entity);
        let public = project_serializable(
            format!("entity:{}", entity.id),
            SearchKind::Entity,
            entity_relations
                .get(&entity.id.to_string())
                .cloned()
                .unwrap_or_default(),
            entity.name.clone(),
            &public_view,
            None,
            None,
            Some(format!("{:?}", entity.kind)),
            None,
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("entity:{}", entity.id),
            SearchKind::Entity,
            entity_relations
                .get(&entity.id.to_string())
                .cloned()
                .unwrap_or_default(),
            entity.name.clone(),
            entity,
            None,
            None,
            Some(format!("{:?}", entity.kind)),
            None,
            settings.max_content_chars as usize,
        );
        documents.push(with_privileged(public, privileged?));
    }
    for book in ordered_books {
        ensure_projection_active(shutdown)?;
        let public_view = guest_book_value(book);
        let public = project_serializable(
            format!("book:{}", book.id),
            SearchKind::Book,
            book_relations
                .get(&book.id.to_string())
                .cloned()
                .unwrap_or_default(),
            book_label(book),
            &public_view,
            None,
            None,
            Some(format!("{:?}", book.state)),
            None,
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("book:{}", book.id),
            SearchKind::Book,
            privileged_book_relations
                .get(&book.id.to_string())
                .cloned()
                .unwrap_or_default(),
            privileged_book_label(book),
            book,
            None,
            None,
            Some(format!("{:?}", book.state)),
            None,
            settings.max_content_chars as usize,
        );
        documents.push(with_privileged(public, privileged?));
    }
    for act in ordered_acts {
        ensure_projection_active(shutdown)?;
        let public_view = guest_act_value(act);
        let public = project_serializable(
            format!("act:{}", act.id),
            SearchKind::Act,
            act_relations
                .get(&act.id.to_string())
                .cloned()
                .unwrap_or_default(),
            REDACTED.to_owned(),
            &public_view,
            None,
            None,
            Some(format!("{:?}", act.state)),
            act.meeting_date.map(|date| date.to_string()),
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("act:{}", act.id),
            SearchKind::Act,
            privileged_act_relations
                .get(&act.id.to_string())
                .cloned()
                .unwrap_or_default(),
            act.title.clone(),
            act,
            None,
            None,
            Some(format!("{:?}", act.state)),
            act.meeting_date.map(|date| date.to_string()),
            settings.max_content_chars as usize,
        );
        documents.push(with_privileged(public, privileged?));
    }
    for follow_up in ordered_follow_ups {
        ensure_projection_active(shutdown)?;
        let relation = act_relations
            .get(&follow_up.act_id.to_string())
            .cloned()
            .unwrap_or_else(|| Relation {
                act_id: Some(follow_up.act_id.to_string()),
                ..Relation::default()
            });
        let privileged_relation = privileged_act_relations
            .get(&follow_up.act_id.to_string())
            .cloned()
            .unwrap_or_else(|| relation.clone());
        let body = format!(
            "{}\n{}\n{}",
            REDACTED,
            follow_up.status.as_str(),
            follow_up
                .due_date
                .map(|date| date.to_string())
                .unwrap_or_default()
        );
        let public = project_text(
            format!("follow_up:{}", follow_up.id),
            SearchKind::FollowUp,
            relation,
            REDACTED.to_owned(),
            body.clone(),
            None,
            None,
            Some(follow_up.status.as_str().to_owned()),
            Some(
                follow_up
                    .due_date
                    .map(|date| date.to_string())
                    .unwrap_or_else(|| format_time(follow_up.created_at)),
            ),
            body.as_bytes(),
            settings.max_content_chars as usize,
        );
        let privileged_body = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            follow_up.title,
            follow_up.detail.as_deref().unwrap_or_default(),
            follow_up.assignee.as_deref().unwrap_or_default(),
            follow_up.assignee_display.as_deref().unwrap_or_default(),
            follow_up.status.as_str(),
            follow_up
                .due_date
                .map(|date| date.to_string())
                .unwrap_or_default(),
            follow_up.created_by
        );
        let privileged = project_text(
            format!("follow_up:{}", follow_up.id),
            SearchKind::FollowUp,
            privileged_relation,
            follow_up.title.clone(),
            privileged_body.clone(),
            Some(follow_up.created_by.clone()),
            None,
            Some(follow_up.status.as_str().to_owned()),
            Some(
                follow_up
                    .due_date
                    .map(|date| date.to_string())
                    .unwrap_or_else(|| format_time(follow_up.created_at)),
            ),
            privileged_body.as_bytes(),
            settings.max_content_chars as usize,
        );
        documents.push(with_privileged(public, privileged));
    }

    documents.extend(project_default_template_registry(
        Ok::<_, String>(default_template_registry),
        settings,
        shutdown,
    )?);
    for (id, raw) in durable.user_templates {
        ensure_projection_active(shutdown)?;
        let value =
            serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| Value::String(raw.clone()));
        let title = value
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| value.get("title").and_then(Value::as_str))
            .unwrap_or(&id)
            .to_owned();
        let public_value = public_template_metadata(&value);
        let public = project_value(
            format!("template:user:{id}"),
            SearchKind::Template,
            Relation::default(),
            title.clone(),
            &public_value,
            None,
            None,
            Some("user_created".to_owned()),
            None,
            raw.as_bytes(),
            settings.max_content_chars as usize,
        );
        let privileged = project_value(
            format!("template:user:{id}"),
            SearchKind::Template,
            Relation::default(),
            title,
            &value,
            None,
            None,
            Some("user_created".to_owned()),
            None,
            raw.as_bytes(),
            settings.max_content_chars as usize,
        );
        documents.push(with_privileged(public, privileged));
    }
    for library in ordered_libraries {
        ensure_projection_active(shutdown)?;
        let public_value = serde_json::json!({
            "id": library.id,
            "tenant_id": library.tenant_id,
            "name": library.name,
            "status": if library.is_archived() { "archived" } else { "active" },
            "updated_at": format_time(library.updated_at),
        });
        let relation = Relation {
            tenant_id: Some(library.tenant_id.to_string()),
            ..Relation::default()
        };
        let public = project_serializable(
            format!("template:library:{}", library.id),
            SearchKind::Template,
            relation.clone(),
            library.name.clone(),
            &public_value,
            None,
            None,
            Some(if library.is_archived() {
                "archived".to_owned()
            } else {
                "active".to_owned()
            }),
            Some(format_time(library.updated_at)),
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("template:library:{}", library.id),
            SearchKind::Template,
            relation,
            library.name.clone(),
            library,
            None,
            None,
            Some(if library.is_archived() {
                "archived".to_owned()
            } else {
                "active".to_owned()
            }),
            Some(format_time(library.updated_at)),
            settings.max_content_chars as usize,
        )?;
        documents.push(with_privileged(public, privileged));
    }
    for revision in ordered_revisions {
        ensure_projection_active(shutdown)?;
        let library_name = template_libraries
            .get(&revision.library_id)
            .map(|library| library.name.as_str())
            .unwrap_or("Biblioteca de modelos");
        let public_value = serde_json::json!({
            "library_id": revision.library_id,
            "tenant_id": revision.tenant_id,
            "revision": revision.revision,
            "created_at": format_time(revision.created_at),
        });
        let relation = Relation {
            tenant_id: Some(revision.tenant_id.to_string()),
            ..Relation::default()
        };
        let title = format!("{library_name} — revisão {}", revision.revision);
        let public = project_serializable(
            format!(
                "template:library:{}:revision:{}",
                revision.library_id, revision.revision
            ),
            SearchKind::Template,
            relation.clone(),
            title.clone(),
            &public_value,
            None,
            None,
            Some("revision".to_owned()),
            Some(format_time(revision.created_at)),
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!(
                "template:library:{}:revision:{}",
                revision.library_id, revision.revision
            ),
            SearchKind::Template,
            relation,
            title,
            revision,
            Some(revision.created_by.clone()),
            None,
            Some("revision".to_owned()),
            Some(format_time(revision.created_at)),
            settings.max_content_chars as usize,
        )?;
        documents.push(with_privileged(public, privileged));
    }

    for diploma in chancela_law::LawCatalog::embedded().diplomas() {
        for article in &diploma.articles {
            ensure_projection_active(shutdown)?;
            let body = format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                diploma.title,
                diploma.reference,
                article.label,
                article.heading,
                article.display_body(),
                article.cross_refs.join(" ")
            );
            documents.push(project_text(
                format!("law:{}:{}", diploma.id, article.number),
                SearchKind::LawArticle,
                Relation::default(),
                format!("{} — {}", article.label, article.heading),
                body.clone(),
                None,
                Some(diploma.reference.clone()),
                Some(format!("{:?}", article.verification)),
                article.source.dr_date.clone(),
                body.as_bytes(),
                settings.max_content_chars as usize,
            ));
        }
    }

    let mut last_event_seq = None;
    for event in &events {
        ensure_projection_active(shutdown)?;
        last_event_seq = Some(last_event_seq.map_or(event.seq, |seq: u64| seq.max(event.seq)));
        let relation = relation_from_scope(
            &format!(
                "{} {}",
                event.scope,
                event
                    .links
                    .iter()
                    .map(|link| link.chain.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            &entity_relations,
            &book_relations,
            &act_relations,
        );
        let public = project_serializable(
            format!("ledger_event:{}", event.seq),
            SearchKind::LedgerEvent,
            relation.clone(),
            REDACTED.to_owned(),
            &serde_json::json!({
                "seq": event.seq,
                "timestamp": format_time(event.timestamp),
                "content": REDACTED,
            }),
            None,
            None,
            Some(REDACTED.to_owned()),
            Some(format_time(event.timestamp)),
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("ledger_event:{}", event.seq),
            SearchKind::LedgerEvent,
            relation,
            event.kind.clone(),
            event,
            Some(event.actor.clone()),
            None,
            Some(event.kind.clone()),
            Some(format_time(event.timestamp)),
            settings.max_content_chars as usize,
        )?;
        documents.push(with_privileged(public, privileged));
    }

    for actionable in actionables {
        ensure_projection_active(shutdown)?;
        let relation = actionable
            .act_id
            .as_deref()
            .and_then(|id| act_relations.get(id).cloned())
            .or_else(|| {
                actionable
                    .book_id
                    .as_deref()
                    .and_then(|id| book_relations.get(id).cloned())
            })
            .or_else(|| {
                actionable
                    .entity_id
                    .as_deref()
                    .and_then(|id| entity_relations.get(id).cloned())
            })
            .unwrap_or_default();
        let mut document = project_text(
            format!("operational_action:{}", actionable.id),
            SearchKind::OperationalAction,
            relation,
            actionable.title,
            actionable.body.clone(),
            None,
            None,
            Some(actionable.status),
            actionable.due_date,
            actionable.body.as_bytes(),
            settings.max_content_chars as usize,
        );
        document.required_permission = Some(actionable.required_permission.as_str().to_owned());
        documents.push(document);
    }

    let mut imported_review_history = durable.imported_review_history;
    for imported in durable.imported_documents {
        ensure_projection_active(shutdown)?;
        let relation = imported
            .act_id
            .and_then(|id| act_relations.get(&id.to_string()).cloned())
            .unwrap_or_else(|| Relation {
                act_id: imported.act_id.map(|id| id.to_string()),
                ..Relation::default()
            });
        let report = serde_json::from_str::<Value>(&imported.technical_validation_report_json)
            .unwrap_or_else(|_| Value::String(imported.technical_validation_report_json.clone()));
        let mut body = flatten_value_to_text(&report);
        for value in [
            imported.filename.as_deref(),
            imported.declared_content_type.as_deref(),
            Some(imported.detected_content_type.as_str()),
            imported.operator_review_note.as_deref(),
            imported.operator_reviewed_by.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            body.push('\n');
            body.push_str(value);
        }
        if let Some(history) = imported_review_history.remove(&imported.id) {
            for entry in history {
                body.push('\n');
                body.push_str(entry.review_status.as_str());
                if let Some(reviewed_at) = entry.reviewed_at {
                    body.push('\n');
                    body.push_str(&format_time(reviewed_at));
                }
                for value in [entry.reviewed_by.as_deref(), entry.review_note.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    body.push('\n');
                    body.push_str(value);
                }
                for guardrail_id in entry.acknowledged_guardrail_ids {
                    body.push('\n');
                    body.push_str(&guardrail_id);
                }
            }
        }
        let source = format!(
            "{}:{}:{}",
            imported.sha256,
            imported.operator_review_status.as_str(),
            body
        );
        documents.push(project_text(
            format!("imported_document:{}", imported.id),
            SearchKind::ImportedDocument,
            relation,
            imported
                .filename
                .clone()
                .unwrap_or_else(|| format!("Documento importado {}", imported.id)),
            body,
            Some(imported.imported_by.clone()),
            None,
            Some(imported.operator_review_status.as_str().to_owned()),
            Some(format_time(imported.imported_at)),
            source.as_bytes(),
            settings.max_content_chars as usize,
        ));
    }

    for (paper, drafts) in durable.paper_imports {
        ensure_projection_active(shutdown)?;
        let relation = relation_for_paper(&paper, &entity_relations, &book_relations);
        let body = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            paper.entity_name,
            paper.entity_nipc,
            paper.book_ref,
            paper.source_filename.as_deref().unwrap_or_default(),
            paper.notes.as_deref().unwrap_or_default(),
            paper.imported_by
        );
        documents.push(project_text(
            format!("paper_book:{}", paper.import_id),
            SearchKind::PaperBook,
            relation.clone(),
            paper
                .source_filename
                .clone()
                .unwrap_or_else(|| format!("Livro em papel {}", paper.book_ref)),
            body.clone(),
            Some(paper.imported_by.clone()),
            None,
            Some(paper.ocr_status.as_str().to_owned()),
            Some(format_time(paper.imported_at)),
            format!("{}:{body}", paper.sha256).as_bytes(),
            settings.max_content_chars as usize,
        ));
        for draft in drafts {
            ensure_projection_active(shutdown)?;
            let body = format!(
                "{}\n{}\n{}\n{}\n{}",
                draft.extracted_text.as_deref().unwrap_or_default(),
                draft.review_note.as_deref().unwrap_or_default(),
                draft.engine_name,
                draft.engine_version.as_deref().unwrap_or_default(),
                draft.reviewed_by.as_deref().unwrap_or_default()
            );
            documents.push(project_text(
                format!("ocr_draft:{}", draft.draft_id),
                SearchKind::OcrDraft,
                relation.clone(),
                format!("OCR {} — {}", paper.book_ref, draft.draft_id),
                body.clone(),
                Some(draft.created_by.clone()),
                None,
                Some(draft.review_status.as_str().to_owned()),
                Some(format_time(draft.created_at)),
                format!(
                    "{}:{}:{body}",
                    draft.text_digest.as_deref().unwrap_or_default(),
                    draft.review_status.as_str()
                )
                .as_bytes(),
                settings.max_content_chars as usize,
            ));
        }
    }

    for generated in durable.generated_documents {
        ensure_projection_active(shutdown)?;
        let relation = act_relations
            .get(&generated.act_id.to_string())
            .cloned()
            .unwrap_or_else(|| Relation {
                act_id: Some(generated.act_id.to_string()),
                ..Relation::default()
            });
        // Generated bytes/spec/layout can carry the same narrative or custom header/footer text as
        // the act. Search the non-content metadata only; the PDF is never loaded by this projection.
        let body = format!(
            "{}\n{}\n{}",
            generated.template_id, generated.profile, generated.pdf_digest
        );
        documents.push(project_text(
            format!("generated_document:{}", generated.id),
            SearchKind::GeneratedDocument,
            relation,
            format!("Documento {}", generated.id),
            body.clone(),
            None,
            None,
            Some(generated.profile),
            Some(format_time(generated.created_at)),
            body.as_bytes(),
            settings.max_content_chars as usize,
        ));
    }

    ensure_projection_active(shutdown)?;
    let (documents, indexed_content_chars, content_budget_exhausted) =
        apply_global_content_budget(documents, settings.max_total_content_chars);
    Ok(ProjectionBuild {
        documents,
        last_event_seq,
        indexed_content_chars,
        content_budget_exhausted,
        projection_utc_date: projection_as_of.date(),
    })
}

/// Hydrate exactly the durable source rows consumed by [`build_corpus`].
pub fn load_projection_inputs(
    store: &Store,
    data_dir: &std::path::Path,
    settings: &chancela_runtime_config::SearchProjectionRuntimeSettings,
    projection_as_of: OffsetDateTime,
) -> Result<ProjectionInputs, String> {
    let source = store
        .load_search_corpus_snapshot()
        .map_err(|error| format!("search source snapshot load failed: {error}"))?;
    let cutoff = projection_as_of.to_offset(UtcOffset::UTC)
        - time::Duration::days(i64::from(settings.search.event_retention_days));
    let events = source
        .ledger
        .events()
        .iter()
        .filter(|event| event.timestamp >= cutoff)
        .cloned()
        .collect::<Vec<_>>();
    let durable = load_durable_rows(store)?;

    let dpia_records = load_unique_records(
        authoritative_document(
            store
                .dpia_records_document()
                .map_err(|error| format!("DPIA document read failed: {error}"))?,
            &data_dir.join("privacy-dpias.json"),
        )?,
        "DPIA document",
        |record: &chancela_action_center::DpiaRecord| record.id,
    )?;
    let breach_playbooks = load_unique_records(
        authoritative_document(
            store
                .breach_playbooks_document()
                .map_err(|error| format!("breach playbook document read failed: {error}"))?,
            &data_dir.join("privacy-breach-playbooks.json"),
        )?,
        "breach playbook document",
        |record: &chancela_action_center::BreachPlaybookRecord| record.id,
    )?;
    let transfer_controls = load_unique_records(
        authoritative_document(
            store
                .transfer_controls_document()
                .map_err(|error| format!("transfer control document read failed: {error}"))?,
            &data_dir.join("privacy-transfer-controls.json"),
        )?,
        "transfer control document",
        |record: &chancela_action_center::TransferControlRecord| record.id,
    )?;

    let now = projection_as_of.to_offset(UtcOffset::UTC);
    let today = now.date();
    let mut alerts = dashboard_alerts(
        &source.entities,
        &source.books,
        &source.acts,
        &source.registry_extracts,
        source.chain_status.is_ok(),
        today,
    );
    let receipt_bytes = authoritative_document(
        store
            .backup_recovery_drill_receipts_document()
            .map_err(|error| format!("backup recovery receipt document read failed: {error}"))?,
        &data_dir.join("backup-recovery-drills.json"),
    )?;
    let receipts = match receipt_bytes {
        Some(bytes) => decode_backup_receipts(&bytes, "backup recovery receipt document")?,
        None => Vec::new(),
    };
    if let Some(alert) = backup_recovery_freshness_alert(&backup_freshness_review(
        &receipts,
        settings.data_management.backup_recovery.clone(),
        now,
    )) {
        alerts.push(alert);
        sort_dashboard_alerts(&mut alerts);
    }

    let mut evidence_by_document =
        HashMap::<String, Vec<StoredGeneratedDocumentDispatchEvidence>>::new();
    for evidence in store
        .generated_document_dispatch_evidence_all()
        .map_err(|error| format!("generated dispatch evidence load failed: {error}"))?
    {
        evidence_by_document
            .entry(evidence.document_id.clone())
            .or_default()
            .push(evidence);
    }
    let generated_dispatch_evidence = durable
        .generated_documents
        .iter()
        .filter(|metadata| source.acts.contains_key(&metadata.act_id))
        .map(|metadata| GeneratedDispatchEvidenceSnapshot {
            document: StoredDocument {
                id: metadata.id.clone(),
                act_id: metadata.act_id,
                template_id: metadata.template_id.clone(),
                pdf_digest: metadata.pdf_digest.clone(),
                profile: metadata.profile.clone(),
                created_at: metadata.created_at,
                pdf_bytes: Vec::new(),
                template_spec_json: None,
                document_layout_json: None,
            },
            evidence: evidence_by_document
                .remove(&metadata.id)
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    let reminders = dashboard_reminders_with_generated_dispatch_evidence(
        ReminderInputs {
            entities: &source.entities,
            books: &source.books,
            acts: &source.acts,
            follow_ups: &source.follow_ups,
            generated_dispatch_evidence: &generated_dispatch_evidence,
            imported_documents: &durable.imported_documents,
            registry_extracts: &source.registry_extracts,
            dpia_records: &dpia_records,
            breach_playbooks: &breach_playbooks,
            transfer_controls: &transfer_controls,
        },
        today,
        &settings.workflow.reminders,
    );
    let actionables = search_actionables_from_rows(alerts, reminders)
        .map_err(|error| format!("Action Center projection encoding failed: {error}"))?;

    Ok(ProjectionInputs {
        entities: source.entities,
        books: source.books,
        acts: source.acts,
        follow_ups: source.follow_ups,
        template_libraries: source.group_template_libraries,
        template_revisions: source.group_template_library_revisions,
        events,
        durable,
        actionables,
    })
}

fn load_durable_rows(store: &Store) -> Result<DurableCorpusRows, String> {
    let imported_documents = store
        .imported_documents(None)
        .map_err(|error| format!("imported document metadata load failed: {error}"))?;
    let mut imported_review_history =
        HashMap::<String, Vec<StoredImportedDocumentReviewHistoryEntry>>::new();
    for entry in store
        .imported_document_review_history_all()
        .map_err(|error| format!("imported review history load failed: {error}"))?
    {
        imported_review_history
            .entry(entry.imported_document_id.clone())
            .or_default()
            .push(entry);
    }
    let mut drafts_by_import = HashMap::<String, Vec<StoredPaperBookOcrDraft>>::new();
    for draft in store
        .paper_book_ocr_drafts_all()
        .map_err(|error| format!("paper OCR draft load failed: {error}"))?
    {
        drafts_by_import
            .entry(draft.import_id.clone())
            .or_default()
            .push(draft);
    }
    let paper_imports = store
        .paper_book_imports(None)
        .map_err(|error| format!("paper import metadata load failed: {error}"))?
        .into_iter()
        .map(|import| {
            let drafts = drafts_by_import
                .remove(&import.import_id)
                .unwrap_or_default();
            (import, drafts)
        })
        .collect();
    Ok(DurableCorpusRows {
        imported_documents,
        imported_review_history,
        paper_imports,
        generated_documents: store
            .document_search_metadata()
            .map_err(|error| format!("generated document metadata load failed: {error}"))?,
        user_templates: store
            .user_templates()
            .map_err(|error| format!("user template load failed: {error}"))?,
    })
}

fn authoritative_document(
    durable: Option<String>,
    legacy_path: &std::path::Path,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(raw) = durable {
        return Ok(Some(raw.into_bytes()));
    }
    match std::fs::read(legacy_path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "failed to read projector sidecar {}: {error}",
            legacy_path.display()
        )),
    }
}

fn load_unique_records<T, K>(
    bytes: Option<Vec<u8>>,
    label: &str,
    id: impl Fn(&T) -> K,
) -> Result<HashMap<K, T>, String>
where
    T: serde::de::DeserializeOwned,
    K: Clone + Eq + std::hash::Hash + std::fmt::Display,
{
    let Some(bytes) = bytes else {
        return Ok(HashMap::new());
    };
    let records = serde_json::from_slice::<Vec<T>>(&bytes)
        .map_err(|error| format!("{label} decoding failed: {error}"))?;
    let mut unique = HashMap::with_capacity(records.len());
    for record in records {
        let record_id = id(&record);
        if unique.insert(record_id.clone(), record).is_some() {
            return Err(format!("{label} contains duplicate id {record_id}"));
        }
    }
    Ok(unique)
}

const MAX_BACKUP_RECEIPTS: usize = 50;
const MAX_BACKUP_ARCHIVE_REF_BYTES: usize = 1024;
const MAX_BACKUP_OPERATOR_NOTES_BYTES: usize = 2000;
const MAX_BACKUP_CUSTODY_LOCATION_BYTES: usize = 512;
const MAX_BACKUP_VERIFICATION_MESSAGES: usize = 8;
const MAX_BACKUP_VERIFICATION_MESSAGE_BYTES: usize = 512;
const ISOLATED_RESTORE_STATUS_VERIFIED: &str = "verified";
const ISOLATED_RESTORE_STATUS_FAILED: &str = "failed";
const ISOLATED_RESTORE_STATUS_NOT_RECORDED: &str = "not_recorded";

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct ProjectorBackupReceipt {
    id: String,
    created_at: String,
    archive: String,
    preflight_ok: bool,
    preflight_ready: bool,
    encrypted: Option<bool>,
    ledger_verified: bool,
    manifest: Option<ProjectorBackupManifestEvidence>,
    #[serde(default)]
    isolated_restore_verified: bool,
    #[serde(default)]
    isolated_restore_verification: ProjectorIsolatedRestoreVerification,
    operator_notes: Option<String>,
    custody_location: Option<String>,
    #[serde(default)]
    restore_executed: bool,
    #[serde(default)]
    live_db_swapped: bool,
    #[serde(default)]
    sidecars_staged: bool,
    #[serde(default)]
    ledger_restored_appended: bool,
    #[serde(default)]
    data_deleted: bool,
    #[serde(default)]
    offsite_custody_proven: bool,
    #[serde(default)]
    legal_archive_certified: bool,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct ProjectorBackupManifestEvidence {
    schema: String,
    version: u32,
    store_schema_version: i64,
    ledger_length: u64,
    ledger_verified: bool,
    member_count: usize,
    sidecar_member_count: usize,
    db_member_present: bool,
    total_member_bytes: u64,
}

#[allow(dead_code)]
#[derive(Default, serde::Deserialize)]
struct ProjectorIsolatedRestoreVerification {
    #[serde(default = "default_isolated_restore_status")]
    status: String,
    #[serde(default)]
    db_snapshot_materialized: bool,
    #[serde(default)]
    db_snapshot_opened: bool,
    #[serde(default)]
    state_loaded: bool,
    #[serde(default)]
    ledger_verified: bool,
    #[serde(default)]
    cleanup_verified: bool,
    #[serde(default)]
    entity_count: usize,
    #[serde(default)]
    book_count: usize,
    #[serde(default)]
    act_count: usize,
    #[serde(default)]
    sidecar_root_count: usize,
    #[serde(default)]
    sidecar_materialized_file_count: usize,
    #[serde(default)]
    sidecar_materialized_bytes: u64,
    #[serde(default)]
    sqlcipher_encryption_verified: Option<bool>,
    #[serde(default)]
    findings: Vec<String>,
    #[serde(default)]
    errors: Vec<String>,
    #[serde(default = "default_isolated_restore_not_recorded_next_step")]
    next_step: String,
}

impl ProjectorIsolatedRestoreVerification {
    fn is_verified(&self) -> bool {
        self.status == ISOLATED_RESTORE_STATUS_VERIFIED
            && self.db_snapshot_materialized
            && self.db_snapshot_opened
            && self.state_loaded
            && self.ledger_verified
            && self.cleanup_verified
    }
}

fn default_isolated_restore_status() -> String {
    ISOLATED_RESTORE_STATUS_NOT_RECORDED.to_owned()
}

fn default_isolated_restore_not_recorded_next_step() -> String {
    "run a non-destructive recovery drill to record isolated snapshot evidence".to_owned()
}

fn decode_backup_receipts(
    bytes: &[u8],
    source_label: &str,
) -> Result<Vec<ProjectorBackupReceipt>, String> {
    let receipts = serde_json::from_slice::<Vec<ProjectorBackupReceipt>>(bytes)
        .map_err(|error| format!("{source_label} decoding failed: {error}"))?;
    let mut normalized = Vec::with_capacity(receipts.len());
    for (index, receipt) in receipts.into_iter().enumerate() {
        let receipt = normalize_backup_receipt(receipt).ok_or_else(|| {
            format!(
                "{source_label} contains a backup recovery receipt rejected by normalization at index {index}"
            )
        })?;
        normalized.push(receipt);
    }
    normalized.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then(left.id.cmp(&right.id))
    });
    normalized.truncate(MAX_BACKUP_RECEIPTS);
    Ok(normalized)
}

fn normalize_backup_receipt(mut receipt: ProjectorBackupReceipt) -> Option<ProjectorBackupReceipt> {
    receipt.id = normalize_backup_scalar(receipt.id, MAX_BACKUP_ARCHIVE_REF_BYTES)?;
    receipt.created_at = normalize_backup_scalar(receipt.created_at, MAX_BACKUP_ARCHIVE_REF_BYTES)?;
    receipt.archive = normalize_backup_scalar(receipt.archive, MAX_BACKUP_ARCHIVE_REF_BYTES)?;
    receipt.operator_notes =
        normalize_backup_optional(receipt.operator_notes, MAX_BACKUP_OPERATOR_NOTES_BYTES);
    receipt.custody_location =
        normalize_backup_optional(receipt.custody_location, MAX_BACKUP_CUSTODY_LOCATION_BYTES);
    receipt.isolated_restore_verification =
        normalize_isolated_restore_verification(receipt.isolated_restore_verification);
    receipt.isolated_restore_verified = receipt.isolated_restore_verification.is_verified();
    receipt.restore_executed = false;
    receipt.live_db_swapped = false;
    receipt.sidecars_staged = false;
    receipt.ledger_restored_appended = false;
    receipt.data_deleted = false;
    receipt.offsite_custody_proven = false;
    receipt.legal_archive_certified = false;
    Some(receipt)
}

fn normalize_isolated_restore_verification(
    mut verification: ProjectorIsolatedRestoreVerification,
) -> ProjectorIsolatedRestoreVerification {
    verification.status = match verification.status.as_str() {
        ISOLATED_RESTORE_STATUS_VERIFIED => ISOLATED_RESTORE_STATUS_VERIFIED.to_owned(),
        ISOLATED_RESTORE_STATUS_FAILED => ISOLATED_RESTORE_STATUS_FAILED.to_owned(),
        ISOLATED_RESTORE_STATUS_NOT_RECORDED => ISOLATED_RESTORE_STATUS_NOT_RECORDED.to_owned(),
        _ => ISOLATED_RESTORE_STATUS_NOT_RECORDED.to_owned(),
    };
    verification.findings = normalize_backup_messages(verification.findings);
    verification.errors = normalize_backup_messages(verification.errors);
    verification.next_step = normalize_backup_scalar(
        verification.next_step,
        MAX_BACKUP_VERIFICATION_MESSAGE_BYTES,
    )
    .unwrap_or_else(default_isolated_restore_not_recorded_next_step);
    if verification.status == ISOLATED_RESTORE_STATUS_NOT_RECORDED {
        return ProjectorIsolatedRestoreVerification::default();
    }
    if verification.status == ISOLATED_RESTORE_STATUS_VERIFIED && !verification.is_verified() {
        verification.status = ISOLATED_RESTORE_STATUS_FAILED.to_owned();
    }
    verification
}

fn normalize_backup_messages(messages: Vec<String>) -> Vec<String> {
    messages
        .into_iter()
        .filter_map(|message| {
            normalize_backup_scalar(message, MAX_BACKUP_VERIFICATION_MESSAGE_BYTES)
        })
        .take(MAX_BACKUP_VERIFICATION_MESSAGES)
        .collect()
}

fn normalize_backup_scalar(value: String, max_bytes: usize) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > max_bytes
        || has_forbidden_backup_control(trimmed, false)
    {
        return None;
    }
    Some(trimmed.to_owned())
}

fn normalize_backup_optional(value: Option<String>, max_bytes: usize) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty()
            || trimmed.len() > max_bytes
            || has_forbidden_backup_control(trimmed, true)
        {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn has_forbidden_backup_control(value: &str, allow_newlines: bool) -> bool {
    value.chars().any(|character| {
        character.is_control() && !(allow_newlines && matches!(character, '\n' | '\r' | '\t'))
    })
}

fn backup_freshness_review(
    receipts: &[ProjectorBackupReceipt],
    policy: chancela_action_center::BackupRecoveryPolicySettings,
    now: OffsetDateTime,
) -> BackupRecoveryFreshnessReview {
    let latest = receipts.first();
    let latest_receipt_age_days = latest
        .and_then(|receipt| OffsetDateTime::parse(&receipt.created_at, &Rfc3339).ok())
        .map(|created_at| {
            let age_days = (now - created_at).whole_days().max(0);
            age_days.min(u32::MAX as i64) as u32
        });
    let status = match latest {
        None => BackupRecoveryFreshnessStatus::NoReceipt,
        Some(receipt)
            if !receipt.preflight_ready
                || !receipt.preflight_ok
                || !receipt.isolated_restore_verified
                || receipt.isolated_restore_verification.status != "verified" =>
        {
            BackupRecoveryFreshnessStatus::Failed
        }
        Some(_) if latest_receipt_age_days.is_none() => BackupRecoveryFreshnessStatus::Failed,
        Some(_)
            if latest_receipt_age_days.unwrap_or(u32::MAX)
                > u32::from(policy.max_drill_age_days) =>
        {
            BackupRecoveryFreshnessStatus::Stale
        }
        Some(_) => BackupRecoveryFreshnessStatus::Fresh,
    };
    BackupRecoveryFreshnessReview {
        generated_at: now.format(&Rfc3339).unwrap_or_default(),
        policy,
        status,
        latest_receipt_id: latest.map(|receipt| receipt.id.clone()),
        latest_receipt_at: latest.map(|receipt| receipt.created_at.clone()),
        latest_receipt_age_days,
        latest_receipt_preflight_ready: latest.map(|receipt| receipt.preflight_ready),
        latest_receipt_isolated_restore_verified: latest
            .map(|receipt| receipt.isolated_restore_verified),
        restore_performed: false,
        db_swap_performed: false,
        offsite_custody_verified: false,
        rpo_rto_certified: false,
        production_backup_policy_certified: false,
    }
}

fn project_default_template_registry<E: std::fmt::Display>(
    registry: Result<chancela_templates::Registry, E>,
    settings: &SearchSettings,
    shutdown: &AtomicBool,
) -> Result<Vec<SearchDocument>, String> {
    let registry = registry
        .map_err(|error| bounded_projection_error("default template registry is invalid", error))?;
    let mut documents = Vec::with_capacity(registry.specs().len());
    for template in registry.specs() {
        ensure_projection_active(shutdown)?;
        documents.push(project_serializable(
            format!("template:{}", template.id),
            SearchKind::Template,
            Relation::default(),
            template.id.clone(),
            template,
            None,
            template.law_references.first().map(|reference| {
                format!(
                    "{} {}",
                    reference.source_label,
                    reference.article.as_deref().unwrap_or_default()
                )
            }),
            Some(format!("{:?}", template.stage)),
            None,
            settings.max_content_chars as usize,
        )?);
    }
    Ok(documents)
}
#[allow(clippy::too_many_arguments)]
fn project_serializable<T: Serialize>(
    id: String,
    kind: SearchKind,
    relation: Relation,
    title: String,
    source: &T,
    author: Option<String>,
    law: Option<String>,
    status: Option<String>,
    occurred_at: Option<String>,
    max_content_chars: usize,
) -> Result<SearchDocument, String> {
    let source_json =
        serde_json::to_vec(source).map_err(|error| format!("search projection failed: {error}"))?;
    let value = serde_json::from_slice::<Value>(&source_json)
        .map_err(|error| format!("search projection failed: {error}"))?;
    Ok(project_value(
        id,
        kind,
        relation,
        title,
        &value,
        author,
        law,
        status,
        occurred_at,
        &source_json,
        max_content_chars,
    ))
}

fn with_privileged(mut public: SearchDocument, privileged: SearchDocument) -> SearchDocument {
    // The privileged serialization is the full source revision, so changes to hidden fields still
    // invalidate the durable projection even when the public view itself is unchanged.
    public.source_version = privileged.source_version;
    public.privileged = Some(SearchDocumentContent {
        title: privileged.title,
        body: privileged.body,
        content_truncated: privileged.content_truncated,
        entity_name: privileged.entity_name,
        book_label: privileged.book_label,
        author: privileged.author,
        law: privileged.law,
        status: privileged.status,
    });
    public
}

#[allow(clippy::too_many_arguments)]
fn project_value(
    id: String,
    kind: SearchKind,
    relation: Relation,
    title: String,
    value: &Value,
    author: Option<String>,
    law: Option<String>,
    status: Option<String>,
    occurred_at: Option<String>,
    source: &[u8],
    max_content_chars: usize,
) -> SearchDocument {
    project_text(
        id,
        kind,
        relation,
        title,
        flatten_value_to_text(value),
        author,
        law,
        status,
        occurred_at,
        source,
        max_content_chars,
    )
}

#[allow(clippy::too_many_arguments)]
fn project_text(
    id: String,
    kind: SearchKind,
    relation: Relation,
    title: String,
    body: String,
    author: Option<String>,
    law: Option<String>,
    status: Option<String>,
    occurred_at: Option<String>,
    source: &[u8],
    max_content_chars: usize,
) -> SearchDocument {
    let (body, content_truncated) = cap_text(&body, max_content_chars);
    SearchDocument {
        id,
        kind,
        tenant_id: relation.tenant_id,
        entity_id: relation.entity_id,
        entity_name: relation.entity_name,
        book_id: relation.book_id,
        book_label: relation.book_label,
        act_id: relation.act_id,
        title,
        body,
        content_truncated,
        author,
        law,
        status,
        required_permission: None,
        occurred_at,
        source_version: digest_hex(source),
        privileged: None,
    }
}

fn cap_text(value: &str, max_chars: usize) -> (String, bool) {
    let mut chars = value.chars();
    let capped: String = chars.by_ref().take(max_chars).collect();
    let truncated = chars.next().is_some();
    (capped, truncated)
}

fn public_template_metadata(value: &Value) -> Value {
    let mut public = serde_json::Map::new();
    if let Value::Object(fields) = value {
        for key in ["id", "name", "title", "family", "stage", "locale"] {
            if let Some(value) = fields.get(key)
                && (value.is_string() || value.is_number() || value.is_boolean())
            {
                public.insert(key.to_owned(), value.clone());
            }
        }
    }
    Value::Object(public)
}

fn flatten_value_to_text(value: &Value) -> String {
    fn visit(value: &Value, key: Option<&str>, out: &mut Vec<String>) {
        if key.is_some_and(sensitive_projection_key) {
            return;
        }
        match value {
            Value::Null => {}
            Value::Bool(value) => out.push(value.to_string()),
            Value::Number(value) => out.push(value.to_string()),
            Value::String(value) => {
                if !value.trim().is_empty() {
                    out.push(value.clone());
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(value, None, out);
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    out.push(key.replace('_', " "));
                    visit(value, Some(key), out);
                }
            }
        }
    }
    let mut out = Vec::new();
    visit(value, None, &mut out);
    out.join("\n")
}

fn sensitive_projection_key(key: &str) -> bool {
    let folded = key.to_ascii_lowercase();
    folded.contains("password")
        || folded.contains("secret")
        || folded.contains("token")
        || folded == "pdf_bytes"
        || folded == "bytes"
}

fn book_label(book: &Book) -> String {
    match book.book_number {
        Some(number) => format!("{:?} n.º {number}", book.kind),
        None => format!("{:?} {}", book.kind, book.id),
    }
}

fn privileged_book_label(book: &Book) -> String {
    book.kind_label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| book_label(book))
}

fn relation_from_scope(
    scope: &str,
    entities: &HashMap<String, Relation>,
    books: &HashMap<String, Relation>,
    acts: &HashMap<String, Relation>,
) -> Relation {
    let mut resolved_entity = None;
    let mut resolved_book = None;
    let mut resolved_act = None;
    let mut resolved_tenant = None;
    for token in scope.split(|character: char| !(character.is_ascii_hexdigit() || character == '-'))
    {
        if Uuid::parse_str(token).is_err() {
            continue;
        }
        if let Some(relation) = acts.get(token) {
            resolved_act = Some(relation.clone());
            continue;
        }
        if let Some(relation) = books.get(token) {
            resolved_book = Some(relation.clone());
            continue;
        }
        if let Some(relation) = entities.get(token) {
            resolved_entity = Some(relation.clone());
            continue;
        }
        if scope.contains("tenant") {
            resolved_tenant = Some(Relation {
                tenant_id: Some(token.to_owned()),
                ..Relation::default()
            });
        }
    }
    resolved_act
        .or(resolved_book)
        .or(resolved_entity)
        .or(resolved_tenant)
        .unwrap_or_default()
}

fn relation_for_paper(
    paper: &StoredPaperBookImportMeta,
    entities: &HashMap<String, Relation>,
    books: &HashMap<String, Relation>,
) -> Relation {
    books
        .get(&paper.book_ref)
        .cloned()
        .or_else(|| entities.get(&paper.entity_ref).cloned())
        .unwrap_or_default()
}

fn digest_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}
