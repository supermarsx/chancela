//! Dashboard endpoint (contract §2.7): the WFL-40 counts plus the recent-events feed.

use std::collections::HashMap;

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use chancela_core::{
    Act, ActId, ActState, Book, BookId, BookKind, BookState, CalendarPreset, Entity, EntityFamily,
    EntityId, EntityKind, EntityProfile, Severity, profile_for, rule_pack_for,
};
use time::{Date, Month, OffsetDateTime};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::dto::{DashboardReminder, DashboardResponse, LedgerEventView, format_date};
use crate::error::ApiError;

const DASHBOARD_REMINDER_LIMIT: usize = 5;

/// `GET /v1/dashboard` — aggregate counts and the last ten ledger events.
pub async fn dashboard(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<DashboardResponse>, ApiError> {
    // RBAC (t64-E3): the dashboard aggregates act data → `act.read` at Global.
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;
    // entities → books → acts → ledger (read locks; the global order).
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;
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
    let reminders = dashboard_reminders(&entities, &books, &acts, OffsetDateTime::now_utc().date());

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
        reminders,
        recent_events,
    }))
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
    use chancela_core::{MeetingChannel, Nipc};
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
