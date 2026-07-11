use std::collections::HashSet;

use chancela_ledger::Event;
use serde::{Deserialize, Deserializer};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime, Time};

use crate::error::ApiError;

pub(crate) const DEFAULT_LEDGER_PAGE_LIMIT: usize = 100;
pub(crate) const MAX_LEDGER_PAGE_LIMIT: usize = 250;

pub(crate) fn normalized_page_limit(limit: Option<usize>) -> usize {
    limit
        .unwrap_or(DEFAULT_LEDGER_PAGE_LIMIT)
        .clamp(1, MAX_LEDGER_PAGE_LIMIT)
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
        scope: Option<String>,
        kind: &[String],
        actor: Option<String>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Self, ApiError> {
        Ok(Self {
            scope: scope.filter(|s| !s.is_empty()),
            kinds: parse_kind_filter(kind),
            actor: actor.filter(|s| !s.is_empty()),
            from: from.map(parse_from_bound).transpose()?,
            to: to.map(parse_to_bound).transpose()?,
        })
    }

    pub(crate) fn matches(&self, event: &Event) -> bool {
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
) -> String {
    let mut parts = vec![format!("cadeia={chain}")];
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
}
