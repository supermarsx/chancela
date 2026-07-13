use std::collections::HashSet;

use chancela_ledger::Event;
use serde::{Deserialize, Deserializer};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime, Time};

use crate::error::ApiError;
use crate::hex::hex;

pub(crate) const DEFAULT_LEDGER_PAGE_LIMIT: usize = 100;
pub(crate) const MAX_LEDGER_PAGE_LIMIT: usize = 250;

pub(crate) fn normalized_page_limit(limit: Option<usize>) -> usize {
    limit
        .unwrap_or(DEFAULT_LEDGER_PAGE_LIMIT)
        .clamp(1, MAX_LEDGER_PAGE_LIMIT)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LedgerOrder {
    Desc,
}

impl LedgerOrder {
    pub(crate) fn from_query(raw: Option<&str>) -> Result<Self, ApiError> {
        match raw.map(str::trim).filter(|value| !value.is_empty()) {
            None => Ok(Self::Desc),
            Some(value) if value.eq_ignore_ascii_case("desc") => Ok(Self::Desc),
            Some(value) if value.eq_ignore_ascii_case("asc") => Err(ApiError::Unprocessable(
                "unsupported ledger order \"asc\"; only desc is supported for before_seq cursors"
                    .to_owned(),
            )),
            Some(value) => Err(ApiError::Unprocessable(format!(
                "invalid ledger order {value:?}; expected desc"
            ))),
        }
    }

    pub(crate) fn as_query_value(self) -> &'static str {
        match self {
            Self::Desc => "desc",
        }
    }

    pub(crate) fn event_order_label(self) -> &'static str {
        match self {
            Self::Desc => "seq_desc",
        }
    }

    pub(crate) fn display_label(self) -> &'static str {
        match self {
            Self::Desc => "desc (seq global decrescente)",
        }
    }
}

pub(crate) fn deserialize_kind_query<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(OneOrMany::One(value)) => vec![value],
        Some(OneOrMany::Many(values)) => values,
    })
}

#[derive(Debug)]
pub(crate) struct LedgerEventFilters {
    pub(crate) query: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) kinds: HashSet<String>,
    pub(crate) actor: Option<String>,
    pub(crate) from: Option<OffsetDateTime>,
    pub(crate) to: Option<UpperBound>,
}

#[derive(Debug)]
pub(crate) enum UpperBound {
    Inclusive(OffsetDateTime),
    Exclusive(OffsetDateTime),
}

impl UpperBound {
    fn contains(&self, timestamp: OffsetDateTime) -> bool {
        match self {
            UpperBound::Inclusive(to) => timestamp <= *to,
            UpperBound::Exclusive(to) => timestamp < *to,
        }
    }
}

impl LedgerEventFilters {
    pub(crate) fn from_parts(
        query: Option<String>,
        scope: Option<String>,
        kind: &[String],
        actor: Option<String>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Self, ApiError> {
        Ok(Self {
            query: normalize_query(query),
            scope: scope.filter(|s| !s.is_empty()),
            kinds: parse_kind_filter(kind),
            actor: actor.filter(|s| !s.is_empty()),
            from: from.map(parse_from_bound).transpose()?,
            to: to.map(parse_to_bound).transpose()?,
        })
    }

    pub(crate) fn matches(&self, event: &Event) -> bool {
        if let Some(query) = &self.query {
            if !event_matches_query(event, query) {
                return false;
            }
        }
        if let Some(scope) = &self.scope {
            if !event.scope.contains(scope) {
                return false;
            }
        }
        if !self.kinds.is_empty() && !self.kinds.contains(&event.kind) {
            return false;
        }
        if let Some(actor) = &self.actor {
            if &event.actor != actor {
                return false;
            }
        }
        if let Some(from) = self.from {
            if event.timestamp < from {
                return false;
            }
        }
        if let Some(to) = &self.to {
            if !to.contains(event.timestamp) {
                return false;
            }
        }
        true
    }
}

fn normalize_query(query: Option<String>) -> Option<String> {
    query
        .map(|q| q.trim().to_lowercase())
        .filter(|q| !q.is_empty())
}

fn contains_query(value: impl AsRef<str>, query: &str) -> bool {
    value.as_ref().to_lowercase().contains(query)
}

fn event_matches_query(event: &Event, query: &str) -> bool {
    contains_query(event.id.to_string(), query)
        || contains_query(event.seq.to_string(), query)
        || contains_query(&event.actor, query)
        || event
            .justification
            .as_deref()
            .is_some_and(|value| contains_query(value, query))
        || contains_query(&event.scope, query)
        || contains_query(&event.kind, query)
        || contains_query(event.timestamp.format(&Rfc3339).unwrap_or_default(), query)
        || contains_query(hex(&event.payload_digest), query)
        || contains_query(hex(&event.prev_hash), query)
        || contains_query(hex(&event.hash), query)
        || event.links.iter().any(|link| {
            contains_query(link.chain.canonical(), query)
                || contains_query(link.seq.to_string(), query)
                || contains_query(hex(&link.prev_hash), query)
        })
}

pub(crate) fn parse_kind_filter(raw: &[String]) -> HashSet<String> {
    raw.iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(crate) fn filter_summary(
    chain: &str,
    filters: &LedgerEventFilters,
    limit: Option<usize>,
    order: Option<LedgerOrder>,
) -> String {
    let mut parts = vec![format!("cadeia={chain}")];
    if let Some(query) = &filters.query {
        parts.push(format!("pesquisa contem {query}"));
    }
    if let Some(scope) = &filters.scope {
        parts.push(format!("scope contem {scope}"));
    }
    if !filters.kinds.is_empty() {
        let mut kinds: Vec<&str> = filters.kinds.iter().map(String::as_str).collect();
        kinds.sort_unstable();
        parts.push(format!("kind={}", kinds.join(",")));
    }
    if let Some(actor) = &filters.actor {
        parts.push(format!("actor={actor}"));
    }
    if let Some(from) = filters.from {
        parts.push(format!(
            "from={}",
            from.format(&Rfc3339).unwrap_or_default()
        ));
    }
    if let Some(to) = &filters.to {
        let value = match to {
            UpperBound::Inclusive(ts) | UpperBound::Exclusive(ts) => {
                ts.format(&Rfc3339).unwrap_or_default()
            }
        };
        parts.push(format!("to={value}"));
    }
    if let Some(limit) = limit {
        parts.push(format!("limit={limit}"));
    }
    if let Some(order) = order {
        parts.push(format!("order={}", order.as_query_value()));
    }
    parts.join("; ")
}

fn parse_from_bound(raw: &str) -> Result<OffsetDateTime, ApiError> {
    if let Ok(ts) = OffsetDateTime::parse(raw, &Rfc3339) {
        return Ok(ts);
    }
    parse_date(raw).map(|date| date.with_time(Time::MIDNIGHT).assume_utc())
}

fn parse_to_bound(raw: &str) -> Result<UpperBound, ApiError> {
    if let Ok(ts) = OffsetDateTime::parse(raw, &Rfc3339) {
        return Ok(UpperBound::Inclusive(ts));
    }
    let date = parse_date(raw)?;
    let next = date.next_day().ok_or_else(|| {
        ApiError::Unprocessable("invalid to date: cannot advance past maximum date".to_owned())
    })?;
    Ok(UpperBound::Exclusive(
        next.with_time(Time::MIDNIGHT).assume_utc(),
    ))
}

fn parse_date(raw: &str) -> Result<Date, ApiError> {
    let fmt = format_description!("[year]-[month]-[day]");
    Date::parse(raw, &fmt).map_err(|_| {
        ApiError::Unprocessable(format!(
            "invalid timestamp {raw:?}; expected RFC 3339 or YYYY-MM-DD"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_and_repeatable_kind_filters_normalize_to_one_set() {
        let raw = vec![
            "book.opened, document.generated".to_owned(),
            "act.sealed".to_owned(),
            " ".to_owned(),
        ];
        let kinds = parse_kind_filter(&raw);
        assert_eq!(kinds.len(), 3);
        assert!(kinds.contains("book.opened"));
        assert!(kinds.contains("document.generated"));
        assert!(kinds.contains("act.sealed"));
    }

    #[test]
    fn query_filter_matches_record_metadata_and_hashes() {
        let mut ledger = chancela_ledger::Ledger::new();
        let event = ledger.append(
            "Amelia.Marques",
            "entity:e1/book:b1",
            "act.sealed",
            Some("Approved by records officer"),
            b"sealed-payload",
        );
        let hash_prefix = hex(&event.hash)[..12].to_owned();
        let payload_prefix = hex(&event.payload_digest)[..12].to_owned();

        let by_actor = LedgerEventFilters::from_parts(
            Some("amelia.marques".to_owned()),
            None,
            &[],
            None,
            None,
            None,
        )
        .expect("actor query");
        assert!(by_actor.matches(event));

        let by_justification = LedgerEventFilters::from_parts(
            Some("records officer".to_owned()),
            None,
            &[],
            None,
            None,
            None,
        )
        .expect("justification query");
        assert!(by_justification.matches(event));

        let by_hash =
            LedgerEventFilters::from_parts(Some(hash_prefix), None, &[], None, None, None)
                .expect("hash query");
        assert!(by_hash.matches(event));

        let by_payload =
            LedgerEventFilters::from_parts(Some(payload_prefix), None, &[], None, None, None)
                .expect("payload query");
        assert!(by_payload.matches(event));
    }

    #[test]
    fn ledger_order_defaults_to_desc_and_rejects_unsupported_values() {
        assert_eq!(LedgerOrder::from_query(None).unwrap(), LedgerOrder::Desc);
        assert_eq!(
            LedgerOrder::from_query(Some(" desc ")).unwrap(),
            LedgerOrder::Desc
        );

        let asc = LedgerOrder::from_query(Some("asc")).unwrap_err();
        assert!(matches!(asc, ApiError::Unprocessable(message) if message.contains("only desc")));

        let random = LedgerOrder::from_query(Some("newest")).unwrap_err();
        assert!(
            matches!(random, ApiError::Unprocessable(message) if message.contains("expected desc"))
        );
    }
}
