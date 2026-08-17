//! Contract tests for the shared Action Center derivation.
//!
//! What this crate promises callers, and what these tests hold it to:
//!
//! * **Alerts and reminders are advisory routing signals, never legal conclusions.** Every
//!   profile-calendar advisory therefore has to keep asserting that it calculated no legal
//!   deadline, and the dispatch-evidence reminders have to keep asserting that nothing was sent.
//!   Those no-claim flags are the product, not decoration, so they are asserted directly.
//! * **Absence of state is not the same as a negative fact.** A book with no termo, an act with
//!   no meeting date, a privacy record with no receipt and a registry extract with no
//!   `valid_until` each have their own arm, and none of them may be silently folded into the
//!   "everything is fine" path.
//! * **The search projection is a redaction boundary.** An actionable a caller reaches with only
//!   `act.read` / `book.read` / `entity.read` must not carry the alert's message or params, and
//!   its id must be stable across runs and independent of prose.
//!
//! Assertions are on codes, keys, params and enum variants — never on the English or pt-PT prose,
//! which is free to change for grammatical reasons.

use std::collections::{BTreeMap, HashMap};

use chancela_action_center::{
    BackupRecoveryFreshnessReview, BackupRecoveryFreshnessStatus, BackupRecoveryPolicySettings,
    BreachPlaybookId, BreachPlaybookRecord, DashboardAction, DashboardAlert, DashboardAlertTarget,
    DashboardI18n, DashboardReminder, DashboardSearchActionable, DashboardTargetLinks, DpiaRecord,
    DpiaRecordId, GeneratedDispatchEvidenceSnapshot, ReminderInputs, TransferControlId,
    TransferControlRecord, WorkflowReminderSettings, WorkflowReminderSourceSettings,
    backup_recovery_freshness_alert, dashboard_alerts,
    dashboard_reminders_with_generated_dispatch_evidence, parse_dashboard_date,
    search_actionables_from_rows, sort_dashboard_alerts, sort_dashboard_reminders,
};
use chancela_authz::Permission;
use chancela_core::{
    Act, ActId, ActState, Attendee, Book, BookId, BookKind, BookState, Convening,
    ConveningRecipient, Entity, EntityFamily, EntityId, EntityKind, LegalHold, MeetingChannel,
    Nipc, PresenceMode, SignatoryCapacity, StatuteOverrides, TermoDeAbertura,
};
use chancela_registry::{RegistryExtract, RegistryOfficer, RegistryProvenance};
use chancela_store::{
    StoredDocument, StoredFollowUp, StoredFollowUpStatus, StoredGeneratedDocumentDispatchEvidence,
    StoredImportedDocumentMeta, StoredImportedDocumentReviewStatus,
};
use serde_json::{Value, json};
use time::{Date, Month, OffsetDateTime};
use uuid::Uuid;

/// The absent-owner communication template the crate special-cases. Duplicated as a literal
/// because the constant itself is `pub(crate)`; if the crate's copy moves, the dispatch-evidence
/// tests below stop producing reminders and fail loudly rather than silently passing.
const ABSENT_OWNER_TEMPLATE: &str = "condominio-comunicacao-ausentes/v1";
/// A real `LifecycleStage::Convocatoria` template from the embedded registry.
const CONVENING_TEMPLATE: &str = "csc-convocatoria-ag/v1";

// ---------------------------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------------------------

fn day(year: i32, month: u8, day: u8) -> Date {
    Date::from_calendar_date(year, Month::try_from(month).expect("month"), day).expect("date")
}

fn today() -> Date {
    day(2026, 6, 15)
}

fn plus_days(base: Date, days: i32) -> Date {
    Date::from_julian_day(base.to_julian_day() + days).expect("in-range date")
}

fn iso(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

fn timestamp() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_780_000_000).expect("timestamp")
}

fn entity_of(kind: EntityKind, name: &str) -> Entity {
    Entity::new(name, Nipc::unvalidated("500000000"), "Lisboa", kind)
}

/// The default fixture entity: an Lda called after the example company the project uses.
fn lda() -> Entity {
    entity_of(EntityKind::SociedadePorQuotas, "Encosto Estrategico Lda")
}

fn complete_termo() -> TermoDeAbertura {
    TermoDeAbertura {
        entity_name: "Encosto Estrategico Lda".to_owned(),
        entity_nipc: "500000000".to_owned(),
        entity_seat: "Lisboa".to_owned(),
        purpose: "livro de atas da assembleia geral".to_owned(),
        opening_date: day(2026, 1, 2),
        required_signatories: vec!["Amelia Marques".to_owned()],
        ..TermoDeAbertura::default()
    }
}

fn open_book(entity_id: EntityId, kind: BookKind) -> Book {
    let mut book = Book::new(entity_id, kind);
    book.open(complete_termo()).expect("book opens");
    book
}

fn created_book(entity_id: EntityId, kind: BookKind) -> Book {
    Book::new(entity_id, kind)
}

fn act_in(book_id: BookId, state: ActState) -> Act {
    let mut act = Act::draft(book_id, "Ata numero um", MeetingChannel::Physical);
    act.state = state;
    act
}

/// An act with every civil-baseline Error element recorded, so a rule pack reports no Error.
fn compliant_act(book_id: BookId, state: ActState) -> Act {
    let mut act = act_in(book_id, state);
    act.meeting_date = Some(day(2026, 3, 10));
    act.place = Some("Sede".to_owned());
    act.attendance_reference = Some("lista-2026-03-10".to_owned());
    act.deliberations = "Aprovada a proposta apresentada.".to_owned();
    act
}

fn provenance(valid_until: Option<&str>) -> RegistryProvenance {
    RegistryProvenance {
        access_code_masked: "****-****-1234".to_owned(),
        retrieved_at: "2026-01-02T00:00:00Z".to_owned(),
        source_url: "https://example.invalid/certidao".to_owned(),
        raw_digest: "0".repeat(64),
        conservatoria: None,
        oficial: None,
        subscribed_on: None,
        valid_until: valid_until.map(str::to_owned),
    }
}

fn extract_with(valid_until: Option<&str>, orgaos: Vec<RegistryOfficer>) -> RegistryExtract {
    RegistryExtract {
        matricula: None,
        nipc: Some("500000000".to_owned()),
        firma: Some("Encosto Estrategico Lda".to_owned()),
        forma_juridica: None,
        legal_form: None,
        sede: None,
        cae: Vec::new(),
        objeto: None,
        capital: None,
        data_constituicao: Some("2015-04-01".to_owned()),
        orgaos,
        inscricoes: Vec::new(),
        anotacoes: Vec::new(),
        provenance: provenance(valid_until),
    }
}

fn officer(role: Option<&str>, cessation: Option<&str>) -> RegistryOfficer {
    RegistryOfficer {
        name: "Amelia Marques".to_owned(),
        role: role.map(str::to_owned),
        appointment_date: Some("2020-01-01".to_owned()),
        cessation_date: cessation.map(str::to_owned),
        source_event: None,
    }
}

/// The four maps `dashboard_alerts` and the reminder projection take, assembled by id.
#[derive(Default)]
struct World {
    entities: HashMap<EntityId, Entity>,
    books: HashMap<BookId, Book>,
    acts: HashMap<ActId, Act>,
    registry: HashMap<EntityId, RegistryExtract>,
}

impl World {
    fn add_entity(&mut self, entity: Entity) -> EntityId {
        let id = entity.id;
        self.entities.insert(id, entity);
        id
    }

    fn add_book(&mut self, book: Book) -> BookId {
        let id = book.id;
        self.books.insert(id, book);
        id
    }

    fn add_act(&mut self, act: Act) -> ActId {
        let id = act.id;
        self.acts.insert(id, act);
        id
    }

    fn alerts(&self, ledger_valid: bool) -> Vec<DashboardAlert> {
        dashboard_alerts(
            &self.entities,
            &self.books,
            &self.acts,
            &self.registry,
            ledger_valid,
            today(),
        )
    }

    /// Alert codes for a healthy ledger, in the order the crate returns them.
    fn codes(&self) -> Vec<String> {
        self.alerts(true)
            .into_iter()
            .map(|alert| alert.code)
            .collect()
    }

    fn reminders(&self, policy: &WorkflowReminderSettings) -> Vec<DashboardReminder> {
        self.reminders_with(policy, ReminderExtras::default())
    }

    fn reminders_with(
        &self,
        policy: &WorkflowReminderSettings,
        extras: ReminderExtras,
    ) -> Vec<DashboardReminder> {
        dashboard_reminders_with_generated_dispatch_evidence(
            ReminderInputs {
                entities: &self.entities,
                books: &self.books,
                acts: &self.acts,
                follow_ups: &extras.follow_ups,
                generated_dispatch_evidence: &extras.dispatch_evidence,
                imported_documents: &extras.imported_documents,
                registry_extracts: &self.registry,
                dpia_records: &extras.dpia_records,
                breach_playbooks: &extras.breach_playbooks,
                transfer_controls: &extras.transfer_controls,
            },
            today(),
            policy,
        )
    }
}

#[derive(Default)]
struct ReminderExtras {
    follow_ups: HashMap<String, StoredFollowUp>,
    dispatch_evidence: Vec<GeneratedDispatchEvidenceSnapshot>,
    imported_documents: Vec<StoredImportedDocumentMeta>,
    dpia_records: HashMap<DpiaRecordId, DpiaRecord>,
    breach_playbooks: HashMap<BreachPlaybookId, BreachPlaybookRecord>,
    transfer_controls: HashMap<TransferControlId, TransferControlRecord>,
}

impl ReminderExtras {
    fn with_follow_up(mut self, follow_up: StoredFollowUp) -> Self {
        self.follow_ups.insert(follow_up.id.clone(), follow_up);
        self
    }

    fn with_imported(mut self, documents: Vec<StoredImportedDocumentMeta>) -> Self {
        self.imported_documents = documents;
        self
    }

    fn with_dispatch(
        mut self,
        document: StoredDocument,
        evidence: Vec<StoredGeneratedDocumentDispatchEvidence>,
    ) -> Self {
        self.dispatch_evidence
            .push(GeneratedDispatchEvidenceSnapshot { document, evidence });
        self
    }

    fn with_dpia(mut self, id: &str, record: DpiaRecord) -> Self {
        self.dpia_records
            .insert(DpiaRecordId(Uuid::parse_str(id).expect("uuid")), record);
        self
    }

    fn with_breach(mut self, id: &str, record: BreachPlaybookRecord) -> Self {
        self.breach_playbooks
            .insert(BreachPlaybookId(Uuid::parse_str(id).expect("uuid")), record);
        self
    }

    fn with_transfer(mut self, id: &str, record: TransferControlRecord) -> Self {
        self.transfer_controls.insert(
            TransferControlId(Uuid::parse_str(id).expect("uuid")),
            record,
        );
        self
    }
}

/// A policy with every source off, so each test can switch on exactly the one it is about.
fn policy_all_off() -> WorkflowReminderSettings {
    WorkflowReminderSettings {
        enabled: true,
        dashboard_limit: 50,
        due_soon_days: 10,
        attendance_lookahead_days: 30,
        sources: WorkflowReminderSourceSettings {
            profile_calendar: false,
            act_follow_ups: false,
            attendance_hygiene: false,
            privacy_control_reviews: false,
        },
    }
}

fn follow_up(act_id: ActId, due: Option<Date>, status: StoredFollowUpStatus) -> StoredFollowUp {
    StoredFollowUp {
        id: format!("follow-up-{}", Uuid::new_v4()),
        act_id,
        agenda_number: Some(2),
        deliberation_index: Some(0),
        title: "Entregar contas".to_owned(),
        detail: Some("Enviar ao contabilista".to_owned()),
        due_date: due,
        assignee: Some("amelia.marques".to_owned()),
        assignee_display: Some("Amelia Marques".to_owned()),
        status,
        created_at: timestamp(),
        created_by: "amelia.marques".to_owned(),
        completed_at: None,
        completed_by: None,
    }
}

fn document(act_id: ActId, template_id: &str) -> StoredDocument {
    StoredDocument {
        id: format!("doc-{}", Uuid::new_v4()),
        act_id,
        template_id: template_id.to_owned(),
        pdf_digest: "0".repeat(64),
        profile: "condominio-dl268/v1".to_owned(),
        created_at: timestamp(),
        pdf_bytes: Vec::new(),
        template_spec_json: None,
        document_layout_json: None,
    }
}

fn dispatch_row(
    document: &StoredDocument,
    recipients: &[&str],
) -> StoredGeneratedDocumentDispatchEvidence {
    StoredGeneratedDocumentDispatchEvidence {
        document_id: document.id.clone(),
        idempotency_key: format!("key-{}", Uuid::new_v4()),
        act_id: document.act_id,
        template_id: document.template_id.clone(),
        actor: "amelia.marques".to_owned(),
        dispatched_at: timestamp(),
        channel: Some("email".to_owned()),
        reference: None,
        evidence_reference: None,
        imported_document_id: None,
        recipients: recipients.iter().map(|name| (*name).to_owned()).collect(),
        operator_note: None,
        recorded_at: timestamp(),
    }
}

fn imported_document(
    act_id: Option<ActId>,
    status: StoredImportedDocumentReviewStatus,
) -> StoredImportedDocumentMeta {
    StoredImportedDocumentMeta {
        id: format!("imported-{}", Uuid::new_v4()),
        act_id,
        filename: Some("digitalizacao.pdf".to_owned()),
        declared_content_type: Some("application/pdf".to_owned()),
        detected_content_type: "application/pdf".to_owned(),
        sha256: "0".repeat(64),
        size_bytes: 1024,
        imported_at: timestamp(),
        imported_by: "amelia.marques".to_owned(),
        operator_review_status: status,
        operator_reviewed_at: None,
        operator_reviewed_by: None,
        operator_review_note: None,
        operator_acknowledged_guardrail_ids: Vec::new(),
        technical_validation_report_json: "{}".to_owned(),
    }
}

fn attendee(name: &str, presence: PresenceMode) -> Attendee {
    Attendee {
        name: name.to_owned(),
        quality: SignatoryCapacity::CondoOwner,
        quality_note: None,
        presence,
        represented_by: None,
        weight: None,
    }
}

fn recipient(name: &str) -> ConveningRecipient {
    ConveningRecipient {
        name: name.to_owned(),
        contact: None,
        channel: None,
        reference: None,
        dispatched_at: None,
    }
}

// The privacy record types are only reachable from outside the crate through serde: `DpiaRecord`
// is exported but `PrivacyRiskLevel` and the receipt types are not, so a caller cannot write the
// struct literal. Deserializing is the supported construction path (it is how chancela-api
// transcodes its own copies into these), so that is what the fixtures use.

fn dpia_record(id: &str, status: &str, receipts: Value) -> DpiaRecord {
    serde_json::from_value(json!({
        "id": id,
        "title": "Registo de tratamento",
        "purpose": "Gestao de atas",
        "legal_basis": "contrato",
        "data_categories": ["identificacao"],
        "subprocessors": [],
        "risk_level": "high",
        "status": status,
        "evidence_receipts": receipts,
        "created_at": "2026-01-02T00:00:00Z",
        "created_by": "amelia.marques",
        "updated_at": "2026-01-02T00:00:00Z",
        "updated_by": "amelia.marques",
    }))
    .expect("dpia record fixture deserializes")
}

fn dpia_receipt(kind: &str, occurred_at: Option<&str>, recorded_at: &str) -> Value {
    json!({
        "id": format!("receipt-{}", Uuid::new_v4()),
        "evidence_type": kind,
        "recorded_at": recorded_at,
        "recorded_by": "amelia.marques",
        "occurred_at": occurred_at,
        "authority_filing_completed": false,
        "legal_review_accepted": false,
        "legal_certification_completed": false,
        "external_delivery_completed": false,
        "dpia_completed": false,
        "compliance_certification_completed": false,
    })
}

fn breach_record(id: &str, status: &str, receipts: Value) -> BreachPlaybookRecord {
    serde_json::from_value(json!({
        "id": id,
        "title": "Plano de resposta a violacoes",
        "scope": "Plataforma",
        "detection_channels": [],
        "containment_steps": [],
        "notification_roles": [],
        "risk_level": "medium",
        "status": status,
        "evidence_receipts": receipts,
        "created_at": "2026-01-02T00:00:00Z",
        "created_by": "amelia.marques",
        "updated_at": "2026-01-02T00:00:00Z",
        "updated_by": "amelia.marques",
    }))
    .expect("breach playbook fixture deserializes")
}

fn transfer_record(id: &str, status: &str, receipts: Value) -> TransferControlRecord {
    serde_json::from_value(json!({
        "id": id,
        "name": "Transferencia para o fornecedor de backup",
        "purpose": "Backup",
        "legal_basis": "clausulas-tipo",
        "data_categories": [],
        "recipient": "Fornecedor",
        "destination_country": "US",
        "transfer_mechanism": "SCC",
        "safeguards": [],
        "risk_level": "medium",
        "status": status,
        "evidence_receipts": receipts,
        "created_at": "2026-01-02T00:00:00Z",
        "created_by": "amelia.marques",
        "updated_at": "2026-01-02T00:00:00Z",
        "updated_by": "amelia.marques",
    }))
    .expect("transfer control fixture deserializes")
}

fn uuid_text(seed: u128) -> String {
    Uuid::from_u128(seed).to_string()
}

// ---------------------------------------------------------------------------------------------
// helpers over the produced rows
// ---------------------------------------------------------------------------------------------

fn find<'a>(alerts: &'a [DashboardAlert], code: &str) -> &'a DashboardAlert {
    alerts
        .iter()
        .find(|alert| alert.code == code)
        .unwrap_or_else(|| {
            panic!(
                "no alert with code {code}; got {:?}",
                alerts.iter().map(|a| &a.code).collect::<Vec<_>>()
            )
        })
}

fn param<'a>(alert: &'a DashboardAlert, key: &str) -> &'a str {
    alert
        .params
        .get(key)
        .unwrap_or_else(|| panic!("alert {} has no param {key}", alert.code))
}

fn reminder_param<'a>(reminder: &'a DashboardReminder, key: &str) -> &'a str {
    reminder
        .params
        .get(key)
        .unwrap_or_else(|| panic!("reminder {} has no param {key}", reminder.source_rule))
}

fn by_rule<'a>(reminders: &'a [DashboardReminder], rule: &str) -> Vec<&'a DashboardReminder> {
    reminders
        .iter()
        .filter(|reminder| reminder.source_rule == rule)
        .collect()
}

fn only<'a>(reminders: &'a [DashboardReminder], rule: &str) -> &'a DashboardReminder {
    let matches = by_rule(reminders, rule);
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one {rule} reminder, got {:?}",
        reminders.iter().map(|r| &r.source_rule).collect::<Vec<_>>()
    );
    matches[0]
}

// ---------------------------------------------------------------------------------------------
// alerts — the empty and degenerate cases
// ---------------------------------------------------------------------------------------------

#[test]
fn an_empty_world_with_a_verified_ledger_produces_nothing() {
    let world = World::default();
    assert!(world.alerts(true).is_empty());
}

#[test]
fn an_unverifiable_ledger_alerts_on_its_own_with_no_object_target() {
    let world = World::default();
    let alerts = world.alerts(false);

    assert_eq!(
        alerts.iter().map(|a| a.code.as_str()).collect::<Vec<_>>(),
        vec!["ledger.integrity.review_required"]
    );
    let alert = &alerts[0];
    assert_eq!(alert.severity, "Error");
    assert_eq!(alert.category, "LedgerIntegrity");
    assert_eq!(alert.label, "ReviewRequired");
    // No entity/book/act exists to blame; only the ledger report is linked.
    assert_eq!(alert.target.entity_id, None);
    assert_eq!(alert.target.book_id, None);
    assert_eq!(alert.target.act_id, None);
    assert_eq!(
        alert.target.links.ledger.as_deref(),
        Some("/v1/ledger/integrity")
    );
    assert!(alert.params.is_empty());
}

// ---------------------------------------------------------------------------------------------
// alerts — book lifecycle
// ---------------------------------------------------------------------------------------------

#[test]
fn an_entity_with_no_book_at_all_is_advised_to_open_one() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());

    let alerts = world.alerts(true);
    let alert = find(&alerts, "entity.book.no_open_book");
    assert_eq!(param(alert, "total_books"), "0");
    assert_eq!(param(alert, "open_books"), "0");
    assert_eq!(
        alert.target.entity_id.as_deref(),
        Some(entity_id.to_string().as_str())
    );
    assert_eq!(
        alert.target.links.ledger,
        Some(format!("/v1/ledger/events?chain=company:{entity_id}"))
    );
    // The advisory carries the statutory references it routes the operator to.
    assert!(!alert.law_refs.is_empty());
}

#[test]
fn a_book_that_exists_but_was_never_opened_does_not_count_as_open() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    world.add_book(created_book(entity_id, BookKind::AssembleiaGeral));

    let alerts = world.alerts(true);
    let alert = find(&alerts, "entity.book.no_open_book");
    assert_eq!(param(alert, "total_books"), "1");
    assert_eq!(param(alert, "open_books"), "0");
    // A `Created` book has no termo, but it is also not open, so the termo advisory is not raised
    // against it — only open books are checked.
    assert!(
        !world
            .codes()
            .contains(&"book.termo_abertura.missing_metadata".to_owned()),
        "a Created book must not be judged against the open-book termo rule"
    );
}

#[test]
fn an_open_book_suppresses_the_no_open_book_advisory() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));

    assert!(
        !world
            .codes()
            .contains(&"entity.book.no_open_book".to_owned())
    );
}

#[test]
fn an_open_book_with_no_termo_names_the_termo_itself_as_the_gap() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let mut book = open_book(entity_id, BookKind::AssembleiaGeral);
    book.termo_abertura = None;
    world.add_book(book);

    let alerts = world.alerts(true);
    let alert = find(&alerts, "book.termo_abertura.missing_metadata");
    assert_eq!(param(alert, "missing_fields"), "termo_abertura");
    assert_eq!(alert.severity, "Warning");
    assert_eq!(alert.label, "ReviewRequired");
}

#[test]
fn whitespace_only_termo_fields_count_as_missing() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let mut book = open_book(entity_id, BookKind::AssembleiaGeral);
    let termo = book.termo_abertura.as_mut().expect("termo");
    termo.entity_name = "   ".to_owned();
    termo.entity_nipc = String::new();
    termo.entity_seat = "\t".to_owned();
    termo.purpose = "\n".to_owned();
    world.add_book(book);

    let alerts = world.alerts(true);
    let alert = find(&alerts, "book.termo_abertura.missing_metadata");
    assert_eq!(
        param(alert, "missing_fields"),
        "entity_name,entity_nipc,entity_seat,purpose"
    );
}

#[test]
fn a_signatory_list_of_blanks_is_as_missing_as_an_empty_one() {
    for signatories in [Vec::new(), vec!["   ".to_owned(), String::new()]] {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        let mut book = open_book(entity_id, BookKind::AssembleiaGeral);
        book.termo_abertura
            .as_mut()
            .expect("termo")
            .required_signatories = signatories.clone();
        world.add_book(book);

        let alerts = world.alerts(true);
        let alert = find(&alerts, "book.termo_abertura.missing_metadata");
        assert_eq!(
            param(alert, "missing_fields"),
            "required_signatories",
            "signatories {signatories:?} should read as missing"
        );
    }
}

#[test]
fn one_named_signatory_among_blanks_is_enough() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let mut book = open_book(entity_id, BookKind::AssembleiaGeral);
    book.termo_abertura
        .as_mut()
        .expect("termo")
        .required_signatories = vec!["  ".to_owned(), "Amelia Marques".to_owned()];
    world.add_book(book);

    assert!(
        !world
            .codes()
            .contains(&"book.termo_abertura.missing_metadata".to_owned())
    );
}

#[test]
fn an_empty_open_book_advises_the_next_ata_number() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let mut book = open_book(entity_id, BookKind::AssembleiaGeral);
    book.last_ata_number = 7;
    world.add_book(book);

    let alerts = world.alerts(true);
    let alert = find(&alerts, "book.acts.none_recorded");
    assert_eq!(param(alert, "next_ata_number"), "8");
}

#[test]
fn the_next_ata_number_saturates_rather_than_wrapping() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let mut book = open_book(entity_id, BookKind::AssembleiaGeral);
    book.last_ata_number = u64::MAX;
    world.add_book(book);

    let alerts = world.alerts(true);
    assert_eq!(
        param(find(&alerts, "book.acts.none_recorded"), "next_ata_number"),
        u64::MAX.to_string()
    );
}

#[test]
fn a_book_holding_an_act_is_not_reported_as_empty() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    world.add_act(act_in(book_id, ActState::Draft));

    assert!(
        !world
            .codes()
            .contains(&"book.acts.none_recorded".to_owned())
    );
}

#[test]
fn a_legal_hold_is_reported_on_a_closed_book_too() {
    // Retention decisions are taken about closed books, so the hold advisory deliberately does
    // not filter on book state — only on the hold being present.
    for state in [BookState::Created, BookState::Open, BookState::Closed] {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        let mut book = open_book(entity_id, BookKind::AssembleiaGeral);
        book.state = state;
        book.legal_hold = Some(LegalHold {
            reason: "litigio pendente".to_owned(),
            actor: "amelia.marques".to_owned(),
            set_at: timestamp(),
        });
        world.add_book(book);

        let alerts = world.alerts(true);
        let alert = find(&alerts, "book.legal_hold.active");
        assert_eq!(alert.category, "ArchiveRetention");
        assert_eq!(param(alert, "legal_hold_actor"), "amelia.marques");
        assert_eq!(param(alert, "legal_hold_reason"), "litigio pendente");
        assert!(
            !param(alert, "legal_hold_set_at").is_empty(),
            "the moment the hold was set is part of the record"
        );
    }
}

#[test]
fn a_book_without_a_hold_raises_no_hold_alert() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));

    assert!(!world.codes().contains(&"book.legal_hold.active".to_owned()));
}

// ---------------------------------------------------------------------------------------------
// alerts — act lifecycle
// ---------------------------------------------------------------------------------------------

#[test]
fn act_lifecycle_alerts_follow_the_recorded_state_machine() {
    // For each state: which lifecycle codes are produced, and what `next_state` is advised.
    let cases: [(ActState, Option<&str>); 8] = [
        (ActState::Draft, Some("Review")),
        (ActState::Review, Some("Convened")),
        (ActState::Convened, Some("Deliberated")),
        (ActState::Deliberated, Some("TextApproved")),
        (ActState::TextApproved, Some("Signing")),
        (ActState::Signing, None),
        (ActState::Sealed, None),
        (ActState::Archived, None),
    ];

    for (state, next) in cases {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
        world.add_act(act_in(book_id, state));

        let alerts = world.alerts(true);
        let codes = alerts.iter().map(|a| a.code.as_str()).collect::<Vec<_>>();

        match next {
            Some(expected_next) => {
                let alert = find(&alerts, "act.lifecycle.advance_available");
                assert_eq!(param(alert, "next_state"), expected_next, "state {state:?}");
                assert_eq!(param(alert, "current_state"), format!("{state:?}"));
                assert!(
                    !codes.contains(&"act.archive.pending"),
                    "an unsealed act in {state:?} is not awaiting archival"
                );
            }
            None => assert!(
                !codes.contains(&"act.lifecycle.advance_available"),
                "{state:?} is terminal for the advance advisory, got {codes:?}"
            ),
        }

        // Only a sealed act is awaiting archival — an archived one has already arrived.
        assert_eq!(
            codes.contains(&"act.archive.pending"),
            state == ActState::Sealed,
            "archive-pending for {state:?}"
        );
    }
}

#[test]
fn an_act_whose_book_is_absent_produces_no_alerts_for_it() {
    let mut world = World::default();
    world.add_entity(lda());
    // A book id nothing resolves — the projection must skip rather than panic or half-render.
    world.add_act(act_in(BookId::new(), ActState::Draft));

    let codes = world.codes();
    assert!(!codes.contains(&"act.lifecycle.advance_available".to_owned()));
    assert!(!codes.contains(&"act.archive.pending".to_owned()));
}

#[test]
fn a_signing_act_with_review_findings_is_flagged_instead_of_ready() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    // A bare draft is missing date, place, attendance and substance — all civil-baseline Errors.
    world.add_act(act_in(book_id, ActState::Signing));

    let alerts = world.alerts(true);
    let codes = alerts.iter().map(|a| a.code.as_str()).collect::<Vec<_>>();
    assert!(codes.contains(&"act.compliance.review_required"));
    assert!(
        !codes.contains(&"act.lifecycle.signing_ready"),
        "the two signing arms are mutually exclusive"
    );

    let alert = find(&alerts, "act.compliance.review_required");
    assert_eq!(alert.severity, "Warning");
    assert_eq!(alert.category, "Compliance");
    assert!(!param(alert, "rule_pack").is_empty());
    assert_eq!(alert.source.as_deref(), Some(param(alert, "rule_pack")));
}

#[test]
fn a_signing_act_with_no_error_findings_is_reported_ready() {
    let mut world = World::default();
    // The foundation pack is the civil baseline alone, so a complete act clears it.
    let entity_id = world.add_entity(entity_of(EntityKind::Fundacao, "Fundacao Exemplo"));
    let book_id = world.add_book(open_book(entity_id, BookKind::GerenciaAdministracao));
    world.add_act(compliant_act(book_id, ActState::Signing));

    let alerts = world.alerts(true);
    let codes = alerts.iter().map(|a| a.code.as_str()).collect::<Vec<_>>();
    assert!(
        codes.contains(&"act.lifecycle.signing_ready"),
        "expected signing_ready, got {codes:?}"
    );
    assert!(!codes.contains(&"act.compliance.review_required"));

    let alert = find(&alerts, "act.lifecycle.signing_ready");
    assert_eq!(alert.severity, "Info");
    assert_eq!(alert.label, "Advisory");
    assert_eq!(alert.category, "ActLifecycle");
}

// ---------------------------------------------------------------------------------------------
// alerts — registry provenance expiry boundaries
// ---------------------------------------------------------------------------------------------

#[test]
fn registry_provenance_expiry_boundaries() {
    // (offset from today, expected code or None) — 30 days is the warning window.
    let cases: [(i32, Option<&str>); 6] = [
        (-1, Some("registry.provenance.expired")),
        (0, Some("registry.provenance.expiring_soon")),
        (1, Some("registry.provenance.expiring_soon")),
        (29, Some("registry.provenance.expiring_soon")),
        (30, Some("registry.provenance.expiring_soon")),
        (31, None),
    ];

    for (offset, expected) in cases {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
        let valid_until = iso(plus_days(today(), offset));
        world
            .registry
            .insert(entity_id, extract_with(Some(&valid_until), Vec::new()));

        let alerts = world.alerts(true);
        let found = alerts
            .iter()
            .find(|alert| alert.category == "RegistryProvenance");
        match expected {
            Some(code) => {
                let alert = found.unwrap_or_else(|| panic!("offset {offset} produced no alert"));
                assert_eq!(alert.code, code, "offset {offset}");
                assert_eq!(param(alert, "days_until"), offset.to_string());
                assert_eq!(param(alert, "valid_until"), valid_until);
                assert_eq!(alert.severity, "Info");
            }
            None => assert!(
                found.is_none(),
                "offset {offset} is outside the warning window and must stay silent"
            ),
        }
    }
}

#[test]
fn registry_provenance_without_a_usable_valid_until_stays_silent() {
    for valid_until in [None, Some("not-a-date"), Some("2026-13-01"), Some("")] {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
        world
            .registry
            .insert(entity_id, extract_with(valid_until, Vec::new()));

        assert!(
            !world
                .alerts(true)
                .iter()
                .any(|alert| alert.category == "RegistryProvenance"),
            "valid_until {valid_until:?} is not a date and must not be treated as one"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// alerts — remuneration governance prompt
// ---------------------------------------------------------------------------------------------

fn remuneration_world(kind: EntityKind, orgaos: Vec<RegistryOfficer>) -> World {
    let mut world = World::default();
    let entity_id = world.add_entity(entity_of(kind, "Encosto Estrategico Lda"));
    world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    world.registry.insert(entity_id, extract_with(None, orgaos));
    world
}

fn has_remuneration_prompt(world: &World) -> bool {
    world
        .codes()
        .iter()
        .any(|code| code.contains("remuneration.setup_recommended"))
}

#[test]
fn an_active_gerente_without_remuneration_minutes_is_prompted() {
    let world = remuneration_world(
        EntityKind::SociedadePorQuotas,
        vec![officer(Some("Gerente"), None)],
    );

    let alerts = world.alerts(true);
    let alert = find(&alerts, "entity.manager_remuneration.setup_recommended");
    assert_eq!(param(alert, "office"), "management");
    assert_eq!(alert.category, "GovernanceSetup");
}

#[test]
fn a_sociedade_anonima_is_prompted_about_administration_instead() {
    let world = remuneration_world(
        EntityKind::SociedadeAnonima,
        vec![officer(Some("Administrador unico"), None)],
    );

    let alerts = world.alerts(true);
    let alert = find(
        &alerts,
        "entity.administrator_remuneration.setup_recommended",
    );
    assert_eq!(param(alert, "office"), "administration");
}

#[test]
fn an_officer_who_has_ceased_does_not_trigger_the_prompt() {
    let world = remuneration_world(
        EntityKind::SociedadePorQuotas,
        vec![officer(Some("Gerente"), Some("2025-12-31"))],
    );
    assert!(!has_remuneration_prompt(&world));
}

#[test]
fn an_officer_with_no_recorded_role_does_not_trigger_the_prompt() {
    let world = remuneration_world(EntityKind::SociedadePorQuotas, vec![officer(None, None)]);
    assert!(!has_remuneration_prompt(&world));
}

#[test]
fn an_entity_with_no_registry_extract_is_never_prompted() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    assert!(!has_remuneration_prompt(&world));
}

#[test]
fn a_condominium_administrator_is_outside_the_prompt() {
    let world = remuneration_world(
        EntityKind::Condominio,
        vec![officer(Some("Administrador"), None)],
    );
    assert!(!has_remuneration_prompt(&world));
}

#[test]
fn a_sealed_act_mentioning_remuneracao_with_accents_silences_the_prompt() {
    let mut world = remuneration_world(
        EntityKind::SociedadePorQuotas,
        vec![officer(Some("Gerente"), None)],
    );
    let book_id = *world.books.keys().next().expect("book");
    let mut act = act_in(book_id, ActState::Sealed);
    act.title = "Fixação da remuneração da gerência".to_owned();
    world.add_act(act);

    assert!(
        !has_remuneration_prompt(&world),
        "accent folding must match the accented spelling operators actually type"
    );
}

#[test]
fn a_remuneration_act_that_is_not_yet_sealed_does_not_silence_the_prompt() {
    let mut world = remuneration_world(
        EntityKind::SociedadePorQuotas,
        vec![officer(Some("Gerente"), None)],
    );
    let book_id = *world.books.keys().next().expect("book");
    let mut act = act_in(book_id, ActState::TextApproved);
    act.deliberations = "Aprovada a remuneracao dos gerentes.".to_owned();
    world.add_act(act);

    assert!(
        has_remuneration_prompt(&world),
        "only a sealed or archived act is evidence the setup was recorded"
    );
}

#[test]
fn a_remuneration_act_belonging_to_another_entity_does_not_silence_the_prompt() {
    let mut world = remuneration_world(
        EntityKind::SociedadePorQuotas,
        vec![officer(Some("Gerente"), None)],
    );
    let other_entity = world.add_entity(entity_of(
        EntityKind::SociedadePorQuotas,
        "Outra Sociedade Lda",
    ));
    let other_book = world.add_book(open_book(other_entity, BookKind::AssembleiaGeral));
    let mut act = act_in(other_book, ActState::Sealed);
    act.deliberations = "Aprovada a remuneracao dos gerentes.".to_owned();
    world.add_act(act);

    assert!(has_remuneration_prompt(&world));
}

// ---------------------------------------------------------------------------------------------
// sorting
// ---------------------------------------------------------------------------------------------

fn bare_alert(code: &str, label: &str, severity: &str) -> DashboardAlert {
    DashboardAlert {
        code: code.to_owned(),
        label: label.to_owned(),
        severity: severity.to_owned(),
        category: "ActLifecycle".to_owned(),
        message: "message".to_owned(),
        params: BTreeMap::new(),
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
        source: None,
        law_refs: Vec::new(),
        action: None,
        recommended_next_steps: Vec::new(),
        i18n: None,
    }
}

#[test]
fn alert_sorting_is_total_and_order_independent() {
    let mut forward = vec![
        bare_alert("b.code", "Advisory", "Info"),
        bare_alert("a.code", "Advisory", "Info"),
        bare_alert("c.code", "ReviewRequired", "Error"),
    ];
    let mut reversed = forward.clone();
    reversed.reverse();

    sort_dashboard_alerts(&mut forward);
    sort_dashboard_alerts(&mut reversed);

    assert_eq!(forward, reversed, "sorting must not depend on input order");
    // Within one label the code breaks the tie.
    assert_eq!(forward[0].code, "a.code");
    assert_eq!(forward[1].code, "b.code");
}

#[test]
fn reminder_sorting_puts_dated_rows_first_in_due_order() {
    let mut reminders = vec![
        bare_reminder("r-undated", ""),
        bare_reminder("r-late", "2026-09-01"),
        bare_reminder("r-early", "2026-07-01"),
        bare_reminder("r-unparseable", "soon"),
    ];
    sort_dashboard_reminders(&mut reminders);

    let order = reminders
        .iter()
        .map(|r| r.source_rule.as_str())
        .collect::<Vec<_>>();
    assert_eq!(order[0], "r-early");
    assert_eq!(order[1], "r-late");
    // An unusable due date sorts last rather than being dropped or treated as urgent.
    assert!(order[2..].contains(&"r-undated"));
    assert!(order[2..].contains(&"r-unparseable"));
}

fn bare_reminder(rule: &str, due_date: &str) -> DashboardReminder {
    DashboardReminder {
        due_date: due_date.to_owned(),
        severity: "Info".to_owned(),
        status: "Upcoming".to_owned(),
        reason: "reason".to_owned(),
        entity_id: "entity".to_owned(),
        entity_name: "Encosto Estrategico Lda".to_owned(),
        source_rule: rule.to_owned(),
        source_profile: "profile".to_owned(),
        params: BTreeMap::new(),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: None,
        recommended_next_steps: Vec::new(),
        i18n: None,
    }
}

#[test]
fn dashboard_alerts_come_back_already_sorted() {
    // The api appends its backup advisory to this list and re-sorts, so the contract is that the
    // list it receives is already in canonical order.
    let mut world = World::default();
    for name in ["Zeta Lda", "Alfa Lda", "Meia Lda"] {
        let entity_id = world.add_entity(entity_of(EntityKind::SociedadePorQuotas, name));
        let mut book = open_book(entity_id, BookKind::AssembleiaGeral);
        book.legal_hold = Some(LegalHold {
            reason: "litigio".to_owned(),
            actor: "amelia.marques".to_owned(),
            set_at: timestamp(),
        });
        world.add_book(book);
    }

    let produced = world.alerts(false);
    let mut resorted = produced.clone();
    sort_dashboard_alerts(&mut resorted);
    assert_eq!(produced, resorted);
}

#[test]
fn book_counts_are_scoped_to_their_own_entity() {
    let mut world = World::default();
    let with_book = world.add_entity(entity_of(EntityKind::SociedadePorQuotas, "Com Livro Lda"));
    let without = world.add_entity(entity_of(EntityKind::SociedadePorQuotas, "Sem Livro Lda"));
    world.add_book(open_book(with_book, BookKind::AssembleiaGeral));

    let alerts = world.alerts(true);
    let no_book_alerts: Vec<&DashboardAlert> = alerts
        .iter()
        .filter(|alert| alert.code == "entity.book.no_open_book")
        .collect();
    assert_eq!(
        no_book_alerts.len(),
        1,
        "only the bookless entity is advised"
    );
    assert_eq!(
        no_book_alerts[0].target.entity_id.as_deref(),
        Some(without.to_string().as_str())
    );
    assert_eq!(param(no_book_alerts[0], "total_books"), "0");
}

#[test]
fn actionables_list_every_alert_before_every_reminder() {
    let alerts = vec![
        targeted_alert("a.two", true, false, false),
        targeted_alert("a.one", true, false, false),
    ];
    let reminders = vec![
        bare_reminder("act-follow-up", "2026-08-01"),
        bare_reminder("act-attendance-missing", "2026-07-01"),
    ];

    let rows = actionables(alerts, reminders);
    let kinds: Vec<&str> = rows
        .iter()
        .map(|row| row.id.split(':').next().expect("prefix"))
        .collect();
    assert_eq!(kinds, vec!["alert", "alert", "reminder", "reminder"]);
    // Each group arrives in its own canonical order.
    assert_eq!(rows[0].title, "a.one");
    assert_eq!(rows[2].due_date.as_deref(), Some("2026-07-01"));
}

#[test]
fn dashboard_dates_parse_only_as_full_iso_calendar_dates() {
    assert_eq!(parse_dashboard_date("2026-06-15"), Some(day(2026, 6, 15)));
    for rejected in [
        "",
        "2026",
        "2026-06",
        "2026-06-31",
        "2026-13-01",
        "x-06-15",
        "2026/06/15",
    ] {
        assert_eq!(
            parse_dashboard_date(rejected),
            None,
            "{rejected:?} is not a calendar date"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// backup recovery freshness
// ---------------------------------------------------------------------------------------------

fn freshness(status: BackupRecoveryFreshnessStatus) -> BackupRecoveryFreshnessReview {
    BackupRecoveryFreshnessReview {
        generated_at: "2026-06-15T00:00:00Z".to_owned(),
        policy: BackupRecoveryPolicySettings::default(),
        status,
        latest_receipt_id: None,
        latest_receipt_at: None,
        latest_receipt_age_days: None,
        latest_receipt_preflight_ready: None,
        latest_receipt_isolated_restore_verified: None,
        restore_performed: false,
        db_swap_performed: false,
        offsite_custody_verified: false,
        rpo_rto_certified: false,
        production_backup_policy_certified: false,
    }
}

#[test]
fn a_fresh_recovery_drill_raises_no_alert() {
    assert!(
        backup_recovery_freshness_alert(&freshness(BackupRecoveryFreshnessStatus::Fresh)).is_none()
    );
}

#[test]
fn every_unfresh_recovery_state_carries_its_status_as_a_param() {
    let cases = [
        (BackupRecoveryFreshnessStatus::NoReceipt, "no_receipt"),
        (BackupRecoveryFreshnessStatus::Stale, "stale"),
        (BackupRecoveryFreshnessStatus::Failed, "failed"),
    ];
    for (status, expected) in cases {
        let alert = backup_recovery_freshness_alert(&freshness(status)).expect("alert");
        assert_eq!(alert.code, "backup.recovery.freshness_advisory");
        assert_eq!(alert.severity, "Warning");
        assert_eq!(param(&alert, "freshness_status"), expected);
        assert_eq!(
            param(&alert, "policy_max_drill_age_days"),
            BackupRecoveryPolicySettings::default()
                .max_drill_age_days
                .to_string()
        );
        // The advisory is about local receipts; it never names an object to open.
        assert_eq!(alert.target.entity_id, None);
        assert_eq!(alert.target.links.ledger, None);
    }
}

#[test]
fn an_absent_recovery_receipt_is_reported_as_not_recorded_rather_than_as_a_date() {
    let alert =
        backup_recovery_freshness_alert(&freshness(BackupRecoveryFreshnessStatus::NoReceipt))
            .expect("alert");
    assert_eq!(param(&alert, "latest_receipt_at"), "not_recorded");
    assert_eq!(param(&alert, "latest_receipt_age_days"), "not_recorded");
}

#[test]
fn a_recorded_recovery_receipt_reports_its_own_age() {
    let mut review = freshness(BackupRecoveryFreshnessStatus::Stale);
    review.latest_receipt_at = Some("2026-01-02T00:00:00Z".to_owned());
    review.latest_receipt_age_days = Some(164);
    let alert = backup_recovery_freshness_alert(&review).expect("alert");
    assert_eq!(param(&alert, "latest_receipt_at"), "2026-01-02T00:00:00Z");
    assert_eq!(param(&alert, "latest_receipt_age_days"), "164");
}

// ---------------------------------------------------------------------------------------------
// search actionables — identity and the redaction boundary
// ---------------------------------------------------------------------------------------------

fn targeted_alert(code: &str, entity: bool, book: bool, act: bool) -> DashboardAlert {
    let mut alert = bare_alert(code, "Advisory", "Info");
    alert.message = "SECRET-MESSAGE".to_owned();
    alert
        .params
        .insert("secret".to_owned(), "SECRET-PARAM".to_owned());
    alert.recommended_next_steps = vec!["SECRET-STEP".to_owned()];
    alert.target.entity_id = entity.then(|| "entity-1".to_owned());
    alert.target.book_id = book.then(|| "book-1".to_owned());
    alert.target.act_id = act.then(|| "act-1".to_owned());
    alert.action = Some(DashboardAction {
        kind: "open_act".to_owned(),
        label_key: "notifications.alert.act.advanceAvailable.action".to_owned(),
        api_href: None,
        route: None,
    });
    alert.i18n = Some(DashboardI18n {
        title_key: "notifications.alert.act.advanceAvailable.title".to_owned(),
        body_key: "notifications.alert.act.advanceAvailable.body".to_owned(),
        action_key: None,
    });
    alert
}

fn actionables(
    alerts: Vec<DashboardAlert>,
    reminders: Vec<DashboardReminder>,
) -> Vec<DashboardSearchActionable> {
    search_actionables_from_rows(alerts, reminders).expect("actionables serialize")
}

#[test]
fn alert_permission_is_derived_from_category_code_then_target_specificity() {
    let mut ledger = bare_alert(
        "ledger.integrity.review_required",
        "ReviewRequired",
        "Error",
    );
    ledger.category = "LedgerIntegrity".to_owned();
    let backup = bare_alert("backup.recovery.freshness_advisory", "Advisory", "Warning");

    let cases: [(DashboardAlert, Permission); 6] = [
        (ledger, Permission::LedgerRead),
        (backup, Permission::DataBackup),
        (
            targeted_alert("a.act", true, true, true),
            Permission::ActRead,
        ),
        (
            targeted_alert("a.book", true, true, false),
            Permission::BookRead,
        ),
        (
            targeted_alert("a.entity", true, false, false),
            Permission::EntityRead,
        ),
        // No target at all still needs *some* permission; the projection refuses to make it public.
        (
            targeted_alert("a.none", false, false, false),
            Permission::ActRead,
        ),
    ];

    for (alert, expected) in cases {
        let code = alert.code.clone();
        let rows = actionables(vec![alert], Vec::new());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].required_permission, expected, "for {code}");
    }
}

#[test]
fn object_scoped_actionable_bodies_withhold_the_message_and_params() {
    for alert in [
        targeted_alert("a.act", true, true, true),
        targeted_alert("a.book", true, true, false),
        targeted_alert("a.entity", true, false, false),
    ] {
        let code = alert.code.clone();
        let rows = actionables(vec![alert], Vec::new());
        let body: Value = serde_json::from_str(&rows[0].body).expect("body is json");

        assert!(body.get("message").is_none(), "{code} leaked its message");
        assert!(body.get("params").is_none(), "{code} leaked its params");
        assert!(body.get("target").is_none(), "{code} leaked its target");
        assert!(
            body.get("recommended_next_steps").is_none(),
            "{code} leaked its next steps"
        );
        assert!(!rows[0].body.contains("SECRET-MESSAGE"));
        assert!(!rows[0].body.contains("SECRET-PARAM"));
        assert!(!rows[0].body.contains("SECRET-STEP"));
        // What a routing surface legitimately needs is still there.
        assert_eq!(body["code"], code.as_str());
        assert!(body.get("i18n").is_some());
        assert!(body.get("action").is_some());
        // The title is the code, never prose.
        assert_eq!(rows[0].title, code);
    }
}

#[test]
fn ledger_and_backup_actionables_carry_the_whole_alert() {
    let mut ledger = targeted_alert("ledger.integrity.review_required", false, false, false);
    ledger.category = "LedgerIntegrity".to_owned();
    let mut backup = targeted_alert("backup.recovery.freshness_advisory", false, false, false);
    backup.category = "BackupRecoveryFreshness".to_owned();

    for alert in [ledger, backup] {
        let code = alert.code.clone();
        let rows = actionables(vec![alert], Vec::new());
        let body: Value = serde_json::from_str(&rows[0].body).expect("body is json");
        assert_eq!(body["message"], "SECRET-MESSAGE", "for {code}");
        assert!(body.get("params").is_some(), "for {code}");
    }
}

#[test]
fn actionable_ids_are_stable_and_independent_of_input_order() {
    let first = targeted_alert("a.one", true, false, false);
    let second = targeted_alert("a.two", true, true, false);

    let forward = actionables(vec![first.clone(), second.clone()], Vec::new());
    let reversed = actionables(vec![second, first], Vec::new());

    let ids =
        |rows: &[DashboardSearchActionable]| rows.iter().map(|r| r.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&forward), ids(&reversed));
    assert!(forward[0].id.starts_with("alert:"));
}

#[test]
fn an_actionable_id_tracks_identity_not_prose() {
    let base = targeted_alert("a.one", true, false, false);

    let mut reworded = base.clone();
    reworded.message = "an entirely different sentence".to_owned();
    reworded.severity = "Warning".to_owned();
    reworded.recommended_next_steps = vec!["different".to_owned()];

    let mut retargeted = base.clone();
    retargeted.target.book_id = Some("book-9".to_owned());

    let id_of = |alert: DashboardAlert| actionables(vec![alert], Vec::new())[0].id.clone();

    assert_eq!(
        id_of(base.clone()),
        id_of(reworded),
        "rewording an alert must not mint a new actionable"
    );
    assert_ne!(
        id_of(base),
        id_of(retargeted),
        "a different target is a different actionable"
    );
}

#[test]
fn privacy_reminders_require_privacy_manage_and_keep_their_reason_as_the_title() {
    for rule in [
        "privacy-dpia-review",
        "privacy-breach-playbook-review",
        "privacy-transfer-control-review",
    ] {
        let mut reminder = bare_reminder(rule, "2026-07-01");
        reminder.reason = "Privacy register item needs review".to_owned();
        let rows = actionables(Vec::new(), vec![reminder]);
        assert_eq!(
            rows[0].required_permission,
            Permission::PrivacyManage,
            "{rule}"
        );
        assert_eq!(rows[0].title, "Privacy register item needs review");
        assert!(rows[0].id.starts_with("reminder:"));
    }
}

#[test]
fn a_non_privacy_reminder_is_act_scoped_and_titled_by_its_rule() {
    let mut reminder = bare_reminder("act-follow-up", "2026-07-01");
    reminder.reason = "SECRET-REASON".to_owned();
    reminder
        .params
        .insert("act_id".to_owned(), "act-7".to_owned());
    reminder
        .params
        .insert("book_id".to_owned(), "book-7".to_owned());

    let rows = actionables(Vec::new(), vec![reminder]);
    assert_eq!(rows[0].required_permission, Permission::ActRead);
    assert_eq!(rows[0].title, "act-follow-up");
    assert!(!rows[0].body.contains("SECRET-REASON"));
    // The scope columns are lifted out of params so the search index can filter on them.
    assert_eq!(rows[0].act_id.as_deref(), Some("act-7"));
    assert_eq!(rows[0].book_id.as_deref(), Some("book-7"));
    assert_eq!(rows[0].due_date.as_deref(), Some("2026-07-01"));
}

// ---------------------------------------------------------------------------------------------
// reminders — the policy envelope
// ---------------------------------------------------------------------------------------------

fn world_with_follow_up() -> (World, ReminderExtras) {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let act_id = world.add_act(act_in(book_id, ActState::Draft));
    let extras = ReminderExtras::default().with_follow_up(follow_up(
        act_id,
        Some(plus_days(today(), 5)),
        StoredFollowUpStatus::Open,
    ));
    (world, extras)
}

#[test]
fn a_disabled_policy_suppresses_every_reminder_source() {
    let (world, extras) = world_with_follow_up();
    let policy = WorkflowReminderSettings {
        enabled: false,
        ..WorkflowReminderSettings::default()
    };

    assert!(world.reminders_with(&policy, extras).is_empty());
}

#[test]
fn a_zero_dashboard_limit_yields_nothing() {
    let (world, extras) = world_with_follow_up();
    let mut policy = policy_all_off();
    policy.sources.act_follow_ups = true;
    policy.dashboard_limit = 0;

    assert!(world.reminders_with(&policy, extras).is_empty());
}

#[test]
fn the_dashboard_limit_truncates_after_sorting_so_the_soonest_survive() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let act_id = world.add_act(act_in(book_id, ActState::Draft));

    let mut extras = ReminderExtras::default();
    for offset in [40, 10, 25] {
        extras = extras.with_follow_up(follow_up(
            act_id,
            Some(plus_days(today(), offset)),
            StoredFollowUpStatus::Open,
        ));
    }

    let mut policy = policy_all_off();
    policy.sources.act_follow_ups = true;
    policy.dashboard_limit = 2;

    let reminders = world.reminders_with(&policy, extras);
    assert_eq!(reminders.len(), 2);
    let due: Vec<&str> = reminders.iter().map(|r| r.due_date.as_str()).collect();
    assert_eq!(
        due,
        vec![iso(plus_days(today(), 10)), iso(plus_days(today(), 25))],
        "truncation must keep the soonest, not an arbitrary two"
    );
}

#[test]
fn the_follow_up_source_switch_is_honoured() {
    let (world, extras) = world_with_follow_up();
    let policy = policy_all_off();
    assert!(
        by_rule(&world.reminders_with(&policy, extras), "act-follow-up").is_empty(),
        "act_follow_ups is off"
    );
}

// ---------------------------------------------------------------------------------------------
// reminders — follow-ups
// ---------------------------------------------------------------------------------------------

fn follow_up_reminders(due_offset: i32, due_soon_days: u16) -> Vec<DashboardReminder> {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let act_id = world.add_act(act_in(book_id, ActState::Draft));
    let extras = ReminderExtras::default().with_follow_up(follow_up(
        act_id,
        Some(plus_days(today(), due_offset)),
        StoredFollowUpStatus::Open,
    ));
    let mut policy = policy_all_off();
    policy.sources.act_follow_ups = true;
    policy.due_soon_days = due_soon_days;
    world.reminders_with(&policy, extras)
}

#[test]
fn follow_up_status_and_severity_at_the_due_soon_boundary() {
    // due_soon_days = 10: yesterday is overdue, today and day 10 are due soon, day 11 is upcoming.
    let cases: [(i32, &str, &str); 5] = [
        (-1, "Overdue", "Warning"),
        (0, "DueSoon", "Info"),
        (9, "DueSoon", "Info"),
        (10, "DueSoon", "Info"),
        (11, "Upcoming", "Advisory"),
    ];
    for (offset, status, severity) in cases {
        let reminders = follow_up_reminders(offset, 10);
        let reminder = only(&reminders, "act-follow-up");
        assert_eq!(reminder.status, status, "offset {offset}");
        assert_eq!(reminder.severity, severity, "offset {offset}");
        assert_eq!(reminder.due_date, iso(plus_days(today(), offset)));
    }
}

#[test]
fn a_completed_or_undated_follow_up_produces_nothing() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let act_id = world.add_act(act_in(book_id, ActState::Draft));

    let extras = ReminderExtras::default()
        .with_follow_up(follow_up(
            act_id,
            Some(plus_days(today(), 3)),
            StoredFollowUpStatus::Completed,
        ))
        .with_follow_up(follow_up(act_id, None, StoredFollowUpStatus::Open));

    let mut policy = policy_all_off();
    policy.sources.act_follow_ups = true;
    assert!(by_rule(&world.reminders_with(&policy, extras), "act-follow-up").is_empty());
}

#[test]
fn a_follow_up_whose_act_is_absent_is_skipped() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));

    let extras = ReminderExtras::default().with_follow_up(follow_up(
        ActId::new(),
        Some(plus_days(today(), 3)),
        StoredFollowUpStatus::Open,
    ));
    let mut policy = policy_all_off();
    policy.sources.act_follow_ups = true;
    assert!(world.reminders_with(&policy, extras).is_empty());
}

#[test]
fn a_follow_up_without_usable_detail_switches_to_the_no_detail_body_key() {
    for detail in [None, Some(String::new()), Some("   ".to_owned())] {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
        let act_id = world.add_act(act_in(book_id, ActState::Draft));

        let mut row = follow_up(
            act_id,
            Some(plus_days(today(), 3)),
            StoredFollowUpStatus::Open,
        );
        row.detail = detail.clone();
        let extras = ReminderExtras::default().with_follow_up(row);

        let mut policy = policy_all_off();
        policy.sources.act_follow_ups = true;
        let reminders = world.reminders_with(&policy, extras);
        let reminder = only(&reminders, "act-follow-up");
        assert_eq!(
            reminder
                .i18n
                .as_ref()
                .expect("follow-up reminders are translated")
                .body_key,
            "notifications.reminder.followUp.bodyNoDetail",
            "detail {detail:?}"
        );
        assert_eq!(reminder_param(reminder, "follow_up_detail"), "");
    }
}

#[test]
fn a_follow_up_with_detail_uses_the_detailed_body_key() {
    let reminders = follow_up_reminders(3, 10);
    let reminder = only(&reminders, "act-follow-up");
    assert_eq!(
        reminder.i18n.as_ref().expect("i18n").body_key,
        "notifications.reminder.followUp.body"
    );
    assert_eq!(
        reminder_param(reminder, "assignee_display"),
        "Amelia Marques"
    );
    assert_eq!(reminder_param(reminder, "agenda_number"), "2");
    assert_eq!(reminder_param(reminder, "deliberation_index"), "0");
}

#[test]
fn an_assignee_display_falls_back_to_the_assignee_id_then_to_empty() {
    // Blank is absent, and the three sites that read operator text now agree on it:
    // `follow_up_reminder`'s display label and its `detail` both go through
    // `trimmed_non_empty`, and `privacy_receipt_sort_key` trims before falling back to
    // `recorded_at`. The third row is the one that used to be wrong: a whitespace-only display
    // label short-circuited the fallback and rendered an empty assignee for a follow-up that
    // has one, which is a false statement about who owns the task.
    let cases: [(Option<&str>, Option<&str>, &str); 6] = [
        (
            Some("amelia.marques"),
            Some("Amelia Marques"),
            "Amelia Marques",
        ),
        (Some("amelia.marques"), None, "amelia.marques"),
        (Some("amelia.marques"), Some("   "), "amelia.marques"),
        (Some("   "), Some("   "), ""),
        (None, Some("   "), ""),
        (None, None, ""),
    ];
    for (assignee, display, expected) in cases {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
        let act_id = world.add_act(act_in(book_id, ActState::Draft));

        let mut row = follow_up(
            act_id,
            Some(plus_days(today(), 3)),
            StoredFollowUpStatus::Open,
        );
        row.assignee = assignee.map(str::to_owned);
        row.assignee_display = display.map(str::to_owned);
        let extras = ReminderExtras::default().with_follow_up(row);

        let mut policy = policy_all_off();
        policy.sources.act_follow_ups = true;
        let reminders = world.reminders_with(&policy, extras);
        assert_eq!(
            reminder_param(only(&reminders, "act-follow-up"), "assignee_display"),
            expected,
            "assignee {assignee:?} display {display:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// reminders — attendance hygiene
// ---------------------------------------------------------------------------------------------

fn attendance_world(configure: impl FnOnce(&mut Act)) -> Vec<DashboardReminder> {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let mut act = act_in(book_id, ActState::Draft);
    act.meeting_date = Some(plus_days(today(), 5));
    configure(&mut act);
    world.add_act(act);

    let mut policy = policy_all_off();
    policy.sources.attendance_hygiene = true;
    policy.attendance_lookahead_days = 30;
    world.reminders(&policy)
}

#[test]
fn an_act_missing_both_attendance_elements_lists_both() {
    let reminders = attendance_world(|_| {});
    let reminder = only(&reminders, "act-attendance-missing");
    assert_eq!(
        reminder_param(reminder, "missing_fields"),
        "attendance_reference,presence_counts_or_attendees"
    );
    assert_eq!(reminder_param(reminder, "days_until"), "5");
    assert_eq!(reminder.due_date, iso(plus_days(today(), 5)));
}

#[test]
fn a_whitespace_attendance_reference_is_still_missing() {
    let reminders = attendance_world(|act| {
        act.attendance_reference = Some("   ".to_owned());
        act.members_present = Some(4);
    });
    let reminder = only(&reminders, "act-attendance-missing");
    assert_eq!(
        reminder_param(reminder, "missing_fields"),
        "attendance_reference"
    );
}

#[test]
fn any_one_presence_signal_satisfies_the_presence_half() {
    let variants: [fn(&mut Act); 3] = [
        |act: &mut Act| act.members_present = Some(3),
        |act: &mut Act| act.members_represented = Some(1),
        |act: &mut Act| act.attendees = vec![attendee("Amelia Marques", PresenceMode::InPerson)],
    ];
    for configure in variants {
        let reminders = attendance_world(|act| {
            act.attendance_reference = Some("lista-1".to_owned());
            configure(act);
        });
        assert!(
            by_rule(&reminders, "act-attendance-missing").is_empty(),
            "a recorded presence signal clears the reminder"
        );
    }
}

#[test]
fn attendance_reminders_stop_at_the_lookahead_boundary() {
    // Exactly at the lookahead the reminder still fires; one day beyond it does not.
    for (offset, expected) in [(30, true), (31, false)] {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
        let mut act = act_in(book_id, ActState::Draft);
        act.meeting_date = Some(plus_days(today(), offset));
        world.add_act(act);

        let mut policy = policy_all_off();
        policy.sources.attendance_hygiene = true;
        policy.attendance_lookahead_days = 30;

        assert_eq!(
            !by_rule(&world.reminders(&policy), "act-attendance-missing").is_empty(),
            expected,
            "meeting {offset} days out"
        );
    }
}

#[test]
fn a_past_meeting_still_raises_the_attendance_gap() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let mut act = act_in(book_id, ActState::Draft);
    act.meeting_date = Some(plus_days(today(), -3));
    world.add_act(act);

    let mut policy = policy_all_off();
    policy.sources.attendance_hygiene = true;
    let reminders = world.reminders(&policy);
    let reminder = only(&reminders, "act-attendance-missing");
    assert_eq!(reminder.status, "Overdue");
    assert_eq!(reminder.severity, "Warning");
}

#[test]
fn an_act_with_no_meeting_date_raises_no_attendance_reminder() {
    let reminders = attendance_world(|act| act.meeting_date = None);
    assert!(by_rule(&reminders, "act-attendance-missing").is_empty());
}

#[test]
fn attendance_hygiene_covers_only_pre_signing_states_in_open_books() {
    for state in [
        ActState::Draft,
        ActState::Review,
        ActState::Convened,
        ActState::Deliberated,
        ActState::TextApproved,
        ActState::Signing,
        ActState::Sealed,
        ActState::Archived,
    ] {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
        let mut act = act_in(book_id, state);
        act.meeting_date = Some(plus_days(today(), 5));
        world.add_act(act);

        let mut policy = policy_all_off();
        policy.sources.attendance_hygiene = true;

        let fired = !by_rule(&world.reminders(&policy), "act-attendance-missing").is_empty();
        let expected = !matches!(
            state,
            ActState::Signing | ActState::Sealed | ActState::Archived
        );
        assert_eq!(fired, expected, "state {state:?}");
    }
}

#[test]
fn a_closed_book_is_outside_the_attendance_work_queue() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let mut book = open_book(entity_id, BookKind::AssembleiaGeral);
    book.state = BookState::Closed;
    let book_id = world.add_book(book);
    let mut act = act_in(book_id, ActState::Draft);
    act.meeting_date = Some(plus_days(today(), 5));
    world.add_act(act);

    let mut policy = policy_all_off();
    policy.sources.attendance_hygiene = true;
    assert!(by_rule(&world.reminders(&policy), "act-attendance-missing").is_empty());
}

#[test]
fn an_entity_whose_kind_contradicts_its_family_is_skipped() {
    // Only reachable by deserializing an inconsistent row; the projection must not derive advice
    // from a record whose legal type and family disagree.
    let mut world = World::default();
    let mut entity = lda();
    entity.family = EntityFamily::Condominium;
    let entity_id = world.add_entity(entity);
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let mut act = act_in(book_id, ActState::Draft);
    act.meeting_date = Some(plus_days(today(), 5));
    world.add_act(act);

    let mut policy = policy_all_off();
    policy.sources.attendance_hygiene = true;
    assert!(world.reminders(&policy).is_empty());
}

// ---------------------------------------------------------------------------------------------
// reminders — convocation notice (never gated by a source switch)
// ---------------------------------------------------------------------------------------------

fn convocation_world(
    notice_days: Option<u16>,
    configure: impl FnOnce(&mut Act),
) -> Vec<DashboardReminder> {
    let mut world = World::default();
    let mut entity = lda();
    entity.statute = Some(StatuteOverrides {
        quorum: None,
        majority: None,
        convocation_notice_days: notice_days,
    });
    let entity_id = world.add_entity(entity);
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let mut act = act_in(book_id, ActState::Draft);
    act.meeting_date = Some(plus_days(today(), 20));
    configure(&mut act);
    world.add_act(act);

    world.reminders(&policy_all_off())
}

#[test]
fn no_configured_notice_period_means_no_notice_advisory() {
    assert!(by_rule(&convocation_world(None, |_| {}), "act-convening-notice").is_empty());

    // Nor when there is no statute overlay at all.
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let mut act = act_in(book_id, ActState::Draft);
    act.meeting_date = Some(plus_days(today(), 20));
    world.add_act(act);
    assert!(by_rule(&world.reminders(&policy_all_off()), "act-convening-notice").is_empty());
}

#[test]
fn recorded_antecedence_at_exactly_the_required_period_satisfies_the_advisory() {
    for (recorded, expected_reminder) in [(15u16, false), (14, true)] {
        let reminders = convocation_world(Some(15), |act| {
            act.convening = Some(Convening {
                antecedence_days: Some(recorded),
                ..Convening::default()
            });
        });
        assert_eq!(
            !by_rule(&reminders, "act-convening-notice").is_empty(),
            expected_reminder,
            "recorded {recorded} days against a required 15"
        );
    }
}

#[test]
fn a_short_notice_advisory_names_the_evidence_state_without_claiming_illegality() {
    let reminders = convocation_world(Some(15), |act| {
        act.convening = Some(Convening {
            antecedence_days: Some(3),
            ..Convening::default()
        });
    });
    let reminder = only(&reminders, "act-convening-notice");
    assert_eq!(
        reminder_param(reminder, "evidence_status"),
        "short_dispatch_evidence"
    );
    assert_eq!(reminder_param(reminder, "antecedence_days"), "3");
    assert_eq!(reminder_param(reminder, "required_notice_days"), "15");
    // The notice due date is the meeting date less the configured period.
    assert_eq!(reminder.due_date, iso(plus_days(today(), 20 - 15)));
    assert_eq!(
        reminder_param(reminder, "legal_sufficiency_claimed"),
        "false"
    );
    assert_eq!(reminder_param(reminder, "local_advisory_only"), "true");
}

#[test]
fn absent_dispatch_evidence_is_distinguished_from_short_evidence() {
    let reminders = convocation_world(Some(15), |_| {});
    let reminder = only(&reminders, "act-convening-notice");
    assert_eq!(
        reminder_param(reminder, "evidence_status"),
        "missing_or_unverifiable_dispatch_evidence"
    );
    assert_eq!(reminder_param(reminder, "antecedence_days"), "");
}

#[test]
fn antecedence_is_derived_from_the_dispatch_date_when_not_recorded_directly() {
    let reminders = convocation_world(Some(15), |act| {
        act.convening = Some(Convening {
            dispatch_date: Some(plus_days(today(), 10)),
            ..Convening::default()
        });
    });
    let reminder = only(&reminders, "act-convening-notice");
    // Meeting is 20 days out, dispatch 10 days out ⇒ 10 days of actual antecedence.
    assert_eq!(reminder_param(reminder, "antecedence_days"), "10");
    assert_eq!(
        reminder_param(reminder, "evidence_status"),
        "short_dispatch_evidence"
    );
    assert_eq!(
        reminder_param(reminder, "dispatch_date"),
        iso(plus_days(today(), 10))
    );
}

#[test]
fn without_a_meeting_date_the_notice_due_date_is_reported_uncomputable() {
    let reminders = convocation_world(Some(15), |act| {
        act.meeting_date = None;
        act.convening = Some(Convening {
            dispatch_date: Some(plus_days(today(), 2)),
            ..Convening::default()
        });
    });
    let reminder = only(&reminders, "act-convening-notice");

    assert_eq!(reminder.due_date, "", "no date may be invented");
    assert_eq!(reminder.status, "Pending");
    assert_eq!(
        reminder_param(reminder, "evidence_status"),
        "missing_meeting_date"
    );
    assert_eq!(
        reminder_param(reminder, "notice_due_date_computable"),
        "false"
    );
    assert_eq!(
        reminder_param(reminder, "notice_due_date_blocked_by"),
        "missing_meeting_date"
    );
    assert_eq!(reminder_param(reminder, "local_deadline_computed"), "false");
    // A meeting date is required before antecedence can be derived from a dispatch date alone.
    assert_eq!(reminder_param(reminder, "antecedence_days"), "");
    assert_eq!(
        reminder.i18n.as_ref().expect("i18n").body_key,
        "notifications.reminder.act.conveningNotice.missingMeetingDate.body"
    );
}

// ---------------------------------------------------------------------------------------------
// reminders — imported documents awaiting review
// ---------------------------------------------------------------------------------------------

#[test]
fn only_the_review_required_import_statuses_produce_a_reminder() {
    let cases = [
        (
            StoredImportedDocumentReviewStatus::OperatorReviewRequired,
            true,
        ),
        (StoredImportedDocumentReviewStatus::OcrReviewRequired, true),
        (
            StoredImportedDocumentReviewStatus::CanonicalConversionReviewRequired,
            true,
        ),
        (
            StoredImportedDocumentReviewStatus::ReviewedNonCanonicalOriginalOnly,
            false,
        ),
        (
            StoredImportedDocumentReviewStatus::RejectedNonCanonicalEvidence,
            false,
        ),
    ];

    for (status, expected) in cases {
        let mut world = World::default();
        let entity_id = world.add_entity(lda());
        let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
        let act_id = world.add_act(act_in(book_id, ActState::Draft));

        let extras =
            ReminderExtras::default().with_imported(vec![imported_document(Some(act_id), status)]);

        let reminders = world.reminders_with(&policy_all_off(), extras);
        let rows = by_rule(&reminders, "imported-document-review-required");
        assert_eq!(!rows.is_empty(), expected, "status {status:?}");
        if expected {
            assert_eq!(
                reminder_param(rows[0], "operator_review_status"),
                status.as_str()
            );
            assert_eq!(rows[0].due_date, "");
            assert_eq!(rows[0].status, "Pending");
            assert_eq!(rows[0].severity, "Advisory");
        }
    }
}

#[test]
fn an_imported_document_with_no_act_is_not_routed_to_one() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));

    let extras = ReminderExtras::default().with_imported(vec![
        imported_document(
            None,
            StoredImportedDocumentReviewStatus::OperatorReviewRequired,
        ),
        imported_document(
            Some(ActId::new()),
            StoredImportedDocumentReviewStatus::OperatorReviewRequired,
        ),
    ]);

    assert!(world.reminders_with(&policy_all_off(), extras).is_empty());
}

// ---------------------------------------------------------------------------------------------
// reminders — generated dispatch evidence
// ---------------------------------------------------------------------------------------------

fn condominium_dispatch_world(
    template_id: &str,
    configure_act: impl FnOnce(&mut Act),
    recorded: &[&str],
) -> Vec<DashboardReminder> {
    let mut world = World::default();
    let entity_id = world.add_entity(entity_of(EntityKind::Condominio, "Condominio Exemplo"));
    let book_id = world.add_book(open_book(entity_id, BookKind::Condominio));
    let mut act = act_in(book_id, ActState::Sealed);
    act.ata_number = Some(1);
    configure_act(&mut act);
    let act_id = world.add_act(act);

    let doc = document(act_id, template_id);
    let evidence = if recorded.is_empty() {
        Vec::new()
    } else {
        vec![dispatch_row(&doc, recorded)]
    };
    let extras = ReminderExtras::default().with_dispatch(doc, evidence);

    world.reminders_with(&policy_all_off(), extras)
}

fn two_absent_owners(act: &mut Act) {
    act.attendees = vec![
        attendee("Amelia Marques", PresenceMode::Absent),
        attendee("Bruno Dias", PresenceMode::Absent),
        attendee("Carla Nunes", PresenceMode::InPerson),
    ];
}

#[test]
fn absent_owner_dispatch_with_no_evidence_is_reported_as_pending() {
    let reminders = condominium_dispatch_world(ABSENT_OWNER_TEMPLATE, two_absent_owners, &[]);
    let reminder = only(&reminders, "absent-owner-dispatch-evidence");

    assert_eq!(
        reminder_param(reminder, "dispatch_evidence_status"),
        "required_pending"
    );
    assert_eq!(reminder_param(reminder, "required_recipient_count"), "2");
    assert_eq!(reminder_param(reminder, "recorded_recipient_count"), "0");
    assert_eq!(reminder_param(reminder, "missing_recipient_count"), "2");
    assert_eq!(reminder_param(reminder, "evidence_row_count"), "0");
    assert_eq!(
        reminder.source_profile,
        "condominium-generated-communication"
    );
}

#[test]
fn partial_absent_owner_evidence_names_the_recipients_still_missing() {
    let reminders = condominium_dispatch_world(
        ABSENT_OWNER_TEMPLATE,
        two_absent_owners,
        &["Amelia Marques"],
    );
    let reminder = only(&reminders, "absent-owner-dispatch-evidence");

    assert_eq!(
        reminder_param(reminder, "dispatch_evidence_status"),
        "operator_evidence_partial"
    );
    assert_eq!(
        reminder_param(reminder, "recorded_recipients"),
        "Amelia Marques"
    );
    assert_eq!(reminder_param(reminder, "missing_recipients"), "Bruno Dias");
}

#[test]
fn recorded_evidence_matches_despite_operator_whitespace() {
    // Operator-recorded evidence is free text a human pasted. A recipient who *was* served must
    // not read as never served because the paste carried a space — that is a false negative on an
    // evidentiary surface, and one the operator cannot clear by recording the evidence again.
    let reminders = condominium_dispatch_world(
        ABSENT_OWNER_TEMPLATE,
        two_absent_owners,
        &["  Amelia Marques  ", "Bruno Dias\t"],
    );
    assert!(
        by_rule(&reminders, "absent-owner-dispatch-evidence").is_empty(),
        "surrounding whitespace must not keep a served recipient in the missing list"
    );
}

#[test]
fn operator_whitespace_still_leaves_genuinely_missing_recipients_missing() {
    // The trim must not become a wildcard: only the recipient actually recorded clears.
    let reminders = condominium_dispatch_world(
        ABSENT_OWNER_TEMPLATE,
        two_absent_owners,
        &[" Amelia Marques "],
    );
    let reminder = only(&reminders, "absent-owner-dispatch-evidence");
    assert_eq!(
        reminder_param(reminder, "dispatch_evidence_status"),
        "operator_evidence_partial"
    );
    assert_eq!(
        reminder_param(reminder, "recorded_recipients"),
        "Amelia Marques"
    );
    assert_eq!(reminder_param(reminder, "missing_recipients"), "Bruno Dias");
}

#[test]
fn an_unrelated_recorded_name_never_counts_as_coverage() {
    let reminders =
        condominium_dispatch_world(ABSENT_OWNER_TEMPLATE, two_absent_owners, &["Carla Nunes"]);
    let reminder = only(&reminders, "absent-owner-dispatch-evidence");
    assert_eq!(
        reminder_param(reminder, "dispatch_evidence_status"),
        "required_pending"
    );
    assert_eq!(reminder_param(reminder, "recorded_recipient_count"), "0");
}

#[test]
fn full_absent_owner_coverage_closes_the_reminder() {
    let reminders = condominium_dispatch_world(
        ABSENT_OWNER_TEMPLATE,
        two_absent_owners,
        &["Amelia Marques", "Bruno Dias"],
    );
    assert!(by_rule(&reminders, "absent-owner-dispatch-evidence").is_empty());
}

#[test]
fn an_unsealed_or_unnumbered_act_raises_no_absent_owner_reminder() {
    let cases: [fn(&mut Act); 4] = [
        // Not sealed.
        |act: &mut Act| {
            two_absent_owners(act);
            act.state = ActState::TextApproved;
        },
        // Sealed but carrying no ata number.
        |act: &mut Act| {
            two_absent_owners(act);
            act.ata_number = None;
        },
        // Sealed and numbered, but nobody was absent.
        |act: &mut Act| {
            act.attendees = vec![attendee("Carla Nunes", PresenceMode::InPerson)];
        },
        // Sealed and numbered with no attendance list at all.
        |_act: &mut Act| {},
    ];
    for configure in cases {
        let reminders = condominium_dispatch_world(ABSENT_OWNER_TEMPLATE, configure, &[]);
        assert!(by_rule(&reminders, "absent-owner-dispatch-evidence").is_empty());
    }
}

#[test]
fn the_absent_owner_rule_is_scoped_to_condominium_entities() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let mut act = act_in(book_id, ActState::Sealed);
    act.ata_number = Some(1);
    two_absent_owners(&mut act);
    let act_id = world.add_act(act);

    let extras = ReminderExtras::default()
        .with_dispatch(document(act_id, ABSENT_OWNER_TEMPLATE), Vec::new());

    assert!(
        by_rule(
            &world.reminders_with(&policy_all_off(), extras),
            "absent-owner-dispatch-evidence"
        )
        .is_empty()
    );
}

#[test]
fn evidence_recorded_against_another_document_does_not_count() {
    let mut world = World::default();
    let entity_id = world.add_entity(entity_of(EntityKind::Condominio, "Condominio Exemplo"));
    let book_id = world.add_book(open_book(entity_id, BookKind::Condominio));
    let mut act = act_in(book_id, ActState::Sealed);
    act.ata_number = Some(1);
    two_absent_owners(&mut act);
    let act_id = world.add_act(act);

    let doc = document(act_id, ABSENT_OWNER_TEMPLATE);
    let other_doc = document(act_id, ABSENT_OWNER_TEMPLATE);
    // Full coverage, but recorded against a different generated document.
    let stray = dispatch_row(&other_doc, &["Amelia Marques", "Bruno Dias"]);

    let extras = ReminderExtras::default().with_dispatch(doc, vec![stray]);

    let reminders = world.reminders_with(&policy_all_off(), extras);
    let reminder = only(&reminders, "absent-owner-dispatch-evidence");
    assert_eq!(
        reminder_param(reminder, "dispatch_evidence_status"),
        "required_pending"
    );
    assert_eq!(reminder_param(reminder, "recorded_recipient_count"), "0");
    // The row is still counted as present in the snapshot, which is a separate fact.
    assert_eq!(reminder_param(reminder, "evidence_row_count"), "1");
}

#[test]
fn a_generated_convening_notice_tracks_its_convocatoria_recipients() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let mut act = act_in(book_id, ActState::Draft);
    act.convening = Some(Convening {
        recipients: vec![
            recipient("Amelia Marques"),
            recipient("Bruno Dias"),
            // Blank and duplicate rows must not inflate the required set.
            recipient("   "),
            recipient("Amelia Marques"),
        ],
        ..Convening::default()
    });
    let act_id = world.add_act(act);

    let doc = document(act_id, CONVENING_TEMPLATE);
    let evidence = vec![dispatch_row(&doc, &["Amelia Marques"])];
    let extras = ReminderExtras::default().with_dispatch(doc, evidence);

    let reminders = world.reminders_with(&policy_all_off(), extras);
    let reminder = only(&reminders, "generated-convening-dispatch-evidence");

    assert_eq!(reminder_param(reminder, "required_recipient_count"), "2");
    assert_eq!(reminder_param(reminder, "missing_recipients"), "Bruno Dias");
    assert_eq!(
        reminder_param(reminder, "dispatch_evidence_status"),
        "operator_evidence_partial"
    );
    // The whole point of the row: operator metadata was recorded, nothing was sent.
    assert_eq!(reminder_param(reminder, "dispatch_completed"), "false");
    assert_eq!(reminder_param(reminder, "completion_basis"), "none");
    assert_eq!(
        reminder_param(reminder, "sending_performed_by_chancela"),
        "false"
    );
    assert_eq!(reminder_param(reminder, "delivery_confirmed"), "false");
    assert_eq!(
        reminder_param(reminder, "legal_notice_completion_claimed"),
        "false"
    );
}

#[test]
fn a_convening_notice_with_no_recipients_produces_no_reminder() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let act_id = world.add_act(act_in(book_id, ActState::Draft));

    let extras =
        ReminderExtras::default().with_dispatch(document(act_id, CONVENING_TEMPLATE), Vec::new());

    assert!(world.reminders_with(&policy_all_off(), extras).is_empty());
}

#[test]
fn a_document_from_an_unrelated_template_is_ignored_by_both_dispatch_rules() {
    let mut world = World::default();
    let entity_id = world.add_entity(lda());
    let book_id = world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    let mut act = act_in(book_id, ActState::Sealed);
    act.ata_number = Some(1);
    two_absent_owners(&mut act);
    act.convening = Some(Convening {
        recipients: vec![recipient("Amelia Marques")],
        ..Convening::default()
    });
    let act_id = world.add_act(act);

    let extras =
        ReminderExtras::default().with_dispatch(document(act_id, "csc-ata-ag/v1"), Vec::new());

    assert!(world.reminders_with(&policy_all_off(), extras).is_empty());
}

// ---------------------------------------------------------------------------------------------
// reminders — privacy register review cadence
// ---------------------------------------------------------------------------------------------

fn privacy_reminders(extras: ReminderExtras, due_soon_days: u16) -> Vec<DashboardReminder> {
    let world = World::default();
    let mut policy = policy_all_off();
    policy.sources.privacy_control_reviews = true;
    policy.due_soon_days = due_soon_days;
    world.reminders_with(&policy, extras)
}

fn dpia_extras(status: &str, receipts: Value) -> ReminderExtras {
    let id = uuid_text(1);
    let record = dpia_record(&id, status, receipts);
    ReminderExtras::default().with_dpia(&id, record)
}

#[test]
fn a_privacy_record_with_no_receipt_is_pending_not_current() {
    let reminders = privacy_reminders(dpia_extras("active", json!([])), 30);
    let reminder = only(&reminders, "privacy-dpia-review");

    assert_eq!(reminder.status, "Pending");
    assert_eq!(reminder.severity, "Advisory");
    assert_eq!(
        reminder.due_date, "",
        "no cadence anchor means no derived date"
    );
    assert_eq!(reminder_param(reminder, "review_status"), "NoReceipt");
    assert_eq!(reminder_param(reminder, "receipt_count"), "0");
    assert_eq!(reminder.entity_id, "privacy");
    assert_eq!(reminder.source_profile, "privacy-dpia");
    // The standing no-claim set the surface exists to carry.
    assert_eq!(reminder_param(reminder, "local_advisory_only"), "true");
    assert_eq!(
        reminder_param(reminder, "authority_notification_claimed"),
        "false"
    );
    assert_eq!(
        reminder_param(reminder, "subject_notification_claimed"),
        "false"
    );
    assert_eq!(
        reminder_param(reminder, "legal_completion_claimed"),
        "false"
    );
    assert_eq!(
        reminder_param(reminder, "authority_filing_claimed"),
        "false"
    );
    assert_eq!(
        reminder_param(reminder, "compliance_certification_claimed"),
        "false"
    );
}

#[test]
fn a_retired_privacy_record_drops_out_of_the_cadence() {
    let reminders = privacy_reminders(dpia_extras("retired", json!([])), 30);
    assert!(reminders.is_empty());
}

#[test]
fn a_record_marked_under_review_reports_that_rather_than_a_date() {
    let receipt = dpia_receipt(
        "review",
        Some("2026-06-01T00:00:00Z"),
        "2026-06-01T00:00:00Z",
    );
    let reminders = privacy_reminders(dpia_extras("under_review", json!([receipt])), 30);
    let reminder = only(&reminders, "privacy-dpia-review");

    assert_eq!(reminder_param(reminder, "review_status"), "UnderReview");
    assert_eq!(reminder.status, "Pending");
    assert_eq!(reminder.severity, "Info");
    assert_eq!(reminder.due_date, "");
    assert_eq!(reminder_param(reminder, "days_until_due"), "");
}

#[test]
fn the_privacy_review_cadence_boundary_is_one_year_from_the_last_receipt() {
    // The interval is 365 days; `due_soon_days` widens the warning, it does not move the anchor.
    let cases: [(i32, &str, &str, &str); 4] = [
        (-400, "Overdue", "Overdue", "Warning"),
        (-366, "Overdue", "Overdue", "Warning"),
        (-365, "DueSoon", "DueSoon", "Info"),
        (-300, "Current", "", ""),
    ];

    for (offset, review_status, dashboard_status, severity) in cases {
        let occurred = format!("{}T00:00:00Z", iso(plus_days(today(), offset)));
        let receipt = dpia_receipt("review", Some(&occurred), "2026-01-01T00:00:00Z");
        let reminders = privacy_reminders(dpia_extras("active", json!([receipt])), 10);

        if review_status == "Current" {
            assert!(
                reminders.is_empty(),
                "a current record raises no reminder (offset {offset})"
            );
            continue;
        }
        let reminder = only(&reminders, "privacy-dpia-review");
        assert_eq!(
            reminder_param(reminder, "review_status"),
            review_status,
            "offset {offset}"
        );
        assert_eq!(reminder.status, dashboard_status, "offset {offset}");
        assert_eq!(reminder.severity, severity, "offset {offset}");
        assert_eq!(
            reminder.due_date,
            iso(plus_days(today(), offset + 365)),
            "offset {offset}"
        );
    }
}

#[test]
fn occurred_at_outranks_recorded_at_and_falls_back_when_blank() {
    // The receipt was recorded recently but happened long ago: the cadence follows when it
    // happened, so the record is overdue rather than current.
    let receipt = dpia_receipt(
        "review",
        Some(&format!("{}T00:00:00Z", iso(plus_days(today(), -400)))),
        "2026-06-01T00:00:00Z",
    );
    let reminders = privacy_reminders(dpia_extras("active", json!([receipt])), 10);
    assert_eq!(
        reminder_param(only(&reminders, "privacy-dpia-review"), "review_status"),
        "Overdue"
    );

    // A blank `occurred_at` falls back to `recorded_at` rather than dropping the receipt.
    let blank = dpia_receipt(
        "review",
        Some("   "),
        &format!("{}T00:00:00Z", iso(plus_days(today(), -400))),
    );
    let reminders = privacy_reminders(dpia_extras("active", json!([blank])), 10);
    assert_eq!(
        reminder_param(only(&reminders, "privacy-dpia-review"), "review_status"),
        "Overdue"
    );
}

#[test]
fn an_unparseable_receipt_timestamp_is_ignored_rather_than_guessed() {
    let receipt = dpia_receipt("review", Some("last tuesday"), "not-a-timestamp");
    let reminders = privacy_reminders(dpia_extras("active", json!([receipt])), 10);
    let reminder = only(&reminders, "privacy-dpia-review");

    assert_eq!(reminder_param(reminder, "review_status"), "NoReceipt");
    // The row is still counted — the receipt exists, its date just cannot anchor a cadence.
    assert_eq!(reminder_param(reminder, "receipt_count"), "1");
    assert_eq!(reminder_param(reminder, "review_receipt_count"), "1");
}

#[test]
fn review_and_drill_receipts_are_counted_separately_but_both_anchor_the_cadence() {
    let drill = dpia_receipt(
        "drill",
        Some(&format!("{}T00:00:00Z", iso(plus_days(today(), -400)))),
        "2026-01-01T00:00:00Z",
    );
    let reminders = privacy_reminders(dpia_extras("active", json!([drill])), 10);
    let reminder = only(&reminders, "privacy-dpia-review");

    assert_eq!(reminder_param(reminder, "review_status"), "Overdue");
    assert_eq!(reminder_param(reminder, "review_receipt_count"), "0");
    assert_eq!(reminder_param(reminder, "drill_receipt_count"), "1");
    assert_eq!(reminder_param(reminder, "last_reviewed_at"), "");
    assert!(!reminder_param(reminder, "last_drill_at").is_empty());
}

#[test]
fn breach_playbooks_and_transfer_controls_run_the_same_cadence() {
    let breach_id = uuid_text(2);
    let transfer_id = uuid_text(3);
    let extras = ReminderExtras::default()
        .with_breach(&breach_id, breach_record(&breach_id, "active", json!([])))
        .with_transfer(
            &transfer_id,
            transfer_record(&transfer_id, "active", json!([])),
        );

    let reminders = privacy_reminders(extras, 30);
    let breach = only(&reminders, "privacy-breach-playbook-review");
    assert_eq!(breach.source_profile, "privacy-breach-playbook");
    assert_eq!(breach.status, "Pending");

    let transfer = only(&reminders, "privacy-transfer-control-review");
    assert_eq!(transfer.source_profile, "privacy-transfer-control");
    assert_eq!(transfer_param_drills(transfer), "0");
}

fn transfer_param_drills(reminder: &DashboardReminder) -> &str {
    reminder_param(reminder, "drill_receipt_count")
}

#[test]
fn the_privacy_source_switch_is_honoured() {
    let world = World::default();
    let extras = dpia_extras("active", json!([]));
    assert!(world.reminders_with(&policy_all_off(), extras).is_empty());
}

// ---------------------------------------------------------------------------------------------
// reminders — profile calendar advisories
// ---------------------------------------------------------------------------------------------

fn calendar_world() -> World {
    let mut world = World::default();
    let mut entity = lda();
    entity.fiscal_year_end = Some("12-31".to_owned());
    let entity_id = world.add_entity(entity);
    world.add_book(open_book(entity_id, BookKind::AssembleiaGeral));
    world
}

fn calendar_policy() -> WorkflowReminderSettings {
    let mut policy = policy_all_off();
    policy.sources.profile_calendar = true;
    policy
}

#[test]
fn a_profile_calendar_advisory_disclaims_every_legal_effect() {
    let world = calendar_world();
    let reminders = world.reminders(&calendar_policy());
    assert!(
        !reminders.is_empty(),
        "an Lda with a recorded fiscal year end has an encoded calendar preset"
    );

    let plan_bearing = reminders
        .iter()
        .find(|reminder| reminder.profile_calendar_plan.is_some())
        .expect("a profile-calendar reminder carries its plan");
    let plan = plan_bearing
        .profile_calendar_plan
        .as_ref()
        .expect("plan present");

    assert!(plan.no_claims.local_advisory_only);
    assert!(!plan.no_claims.legal_deadline_authority_claimed);
    assert!(!plan.no_claims.legal_calendar_authority_claimed);
    assert!(!plan.no_claims.legal_compliance_claimed);
    assert!(!plan.no_claims.compliance_status_claimed);
    assert!(!plan.no_claims.workflow_completion_claimed);
    assert!(!plan.no_claims.external_delivery_claimed);
    assert!(!plan.no_claims.external_calendar_sync_claimed);
    assert!(!plan.no_claims.webhook_delivery_claimed);
    assert!(!plan.no_claims.legal_review_claimed);
    assert!(!plan.no_claims.dre_verification_claimed);
    assert!(!plan.no_claims.provider_effect_claimed);
    assert!(!plan.no_claims.certification_claimed);
    // Whatever the preset computed, it is a local plan date and never a legal deadline.
    assert!(!plan.evaluation.legal_deadline_calculated);
    assert_eq!(
        reminder_param(plan_bearing, "legal_deadline_calculated"),
        "false"
    );
    assert_eq!(plan_bearing.severity, "Advisory");
    assert_eq!(plan_bearing.source_rule, plan.preset_id);
}

#[test]
fn a_scheduled_calendar_advisory_is_suppressed_by_a_sealed_meeting_in_the_due_year() {
    let world = calendar_world();
    let policy = calendar_policy();

    let scheduled = world
        .reminders(&policy)
        .into_iter()
        .find(|reminder| {
            reminder
                .profile_calendar_plan
                .as_ref()
                .is_some_and(|plan| plan.evaluation.local_due_date_calculated)
        })
        .expect("at least one preset resolves to a local date");
    let due_year = parse_dashboard_date(&scheduled.due_date)
        .expect("a scheduled advisory carries a parseable date")
        .year();

    // Record the meeting the preset is asking about, sealed, in that year.
    let mut world = world;
    let book_id = *world.books.keys().next().expect("book");
    let mut act = act_in(book_id, ActState::Sealed);
    act.meeting_date = Some(day(due_year, 3, 30));
    world.add_act(act);

    assert!(
        by_rule(&world.reminders(&policy), &scheduled.source_rule).is_empty(),
        "a sealed general-meeting act in the due year answers the advisory"
    );
}

#[test]
fn a_meeting_in_the_wrong_year_or_the_wrong_book_does_not_suppress_the_advisory() {
    let world = calendar_world();
    let policy = calendar_policy();
    let scheduled = world
        .reminders(&policy)
        .into_iter()
        .find(|reminder| {
            reminder
                .profile_calendar_plan
                .as_ref()
                .is_some_and(|plan| plan.evaluation.local_due_date_calculated)
        })
        .expect("a scheduled advisory");
    let due_year = parse_dashboard_date(&scheduled.due_date)
        .expect("parseable")
        .year();

    // Right year, wrong organ: the signal is scoped to the general-assembly book.
    let mut wrong_book = calendar_world();
    let entity_id = *wrong_book.entities.keys().next().expect("entity");
    let other = wrong_book.add_book(open_book(entity_id, BookKind::ConselhoFiscal));
    let mut act = act_in(other, ActState::Sealed);
    act.meeting_date = Some(day(due_year, 3, 30));
    wrong_book.add_act(act);
    assert!(
        !by_rule(&wrong_book.reminders(&policy), &scheduled.source_rule).is_empty(),
        "a fiscal-council meeting is not the general meeting the preset asks about"
    );

    // Right organ, wrong year.
    let mut wrong_year = calendar_world();
    let book_id = *wrong_year.books.keys().next().expect("book");
    let mut act = act_in(book_id, ActState::Sealed);
    act.meeting_date = Some(day(due_year - 1, 3, 30));
    wrong_year.add_act(act);
    assert!(!by_rule(&wrong_year.reminders(&policy), &scheduled.source_rule).is_empty());
}

#[test]
fn an_unsealed_meeting_does_not_suppress_the_calendar_advisory() {
    let world = calendar_world();
    let policy = calendar_policy();
    let scheduled = world
        .reminders(&policy)
        .into_iter()
        .find(|reminder| {
            reminder
                .profile_calendar_plan
                .as_ref()
                .is_some_and(|plan| plan.evaluation.local_due_date_calculated)
        })
        .expect("a scheduled advisory");
    let due_year = parse_dashboard_date(&scheduled.due_date)
        .expect("parseable")
        .year();

    let mut world = calendar_world();
    let book_id = *world.books.keys().next().expect("book");
    let mut act = act_in(book_id, ActState::TextApproved);
    act.meeting_date = Some(day(due_year, 3, 30));
    world.add_act(act);

    assert!(
        !by_rule(&world.reminders(&policy), &scheduled.source_rule).is_empty(),
        "only a sealed or archived act is evidence the meeting happened"
    );
}

#[test]
fn the_profile_calendar_source_switch_is_honoured() {
    let world = calendar_world();
    assert!(world.reminders(&policy_all_off()).is_empty());
}
