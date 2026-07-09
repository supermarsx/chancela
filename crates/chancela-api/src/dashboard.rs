//! Dashboard endpoint (contract §2.7): the WFL-40 counts plus the recent-events feed.

use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use chancela_core::{
    Act, ActId, ActState, Book, BookId, BookKind, BookState, CalendarPreset, Entity, EntityFamily,
    EntityId, EntityKind, EntityProfile, Severity, profile_for, rule_pack_for,
};
use chancela_registry::RegistryExtract;
use time::{Date, Month, OffsetDateTime};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::dto::{
    DashboardActStateCounts, DashboardAlert, DashboardAlertTarget, DashboardCurrentWork,
    DashboardOpenBook, DashboardReminder, DashboardResponse, DashboardTargetLinks, LedgerEventView,
    compute_expired, format_date,
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
    let reminders = dashboard_reminders(&entities, &books, &acts, today);

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
        });
    }

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

fn dashboard_alert_params<const N: usize>(
    entries: [(&str, String); N],
) -> BTreeMap<String, String> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
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
    today: Date,
) -> Vec<DashboardReminder> {
    let mut reminders = entities
        .values()
        .flat_map(|entity| annual_general_meeting_reminders(entity, books, acts, today))
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
            profile_calendar_reminder(entity, &profile, preset, books, acts, today)
        })
        .collect()
}

fn profile_calendar_reminder(
    entity: &Entity,
    profile: &EntityProfile,
    preset: &CalendarPreset,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    today: Date,
) -> Option<DashboardReminder> {
    let months_after_fiscal_year_end = preset.months_after_fiscal_year_end?;

    let parsed_fiscal_year_end = parse_fiscal_year_end(entity.fiscal_year_end.as_deref());
    let fiscal_year_end = parsed_fiscal_year_end.unwrap_or(DEFAULT_FISCAL_YEAR_END);
    let due_date =
        annual_due_date_for_year(today.year(), fiscal_year_end, months_after_fiscal_year_end);
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
    })
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
    use chancela_registry::{RegistryExtract, RegistryProvenance};
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
    fn missing_fiscal_year_uses_default_for_profile_calendar_reminder() {
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let mut entities = HashMap::new();
        entities.insert(entity.id, entity.clone());

        let reminders = dashboard_reminders(
            &entities,
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

        let reminders = dashboard_reminders(&entities, &books, &acts, date!(2026 - 07 - 09));

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
            date!(2026 - 01 - 15),
        );

        assert_eq!(reminders.len(), 2);
        assert_eq!(reminders[0].entity_id, first_id);
        assert_eq!(reminders[1].entity_id, second_id);
        assert_eq!(reminders[0].due_date, reminders[1].due_date);
        assert_eq!(reminders[0].entity_name, reminders[1].entity_name);
    }
}
