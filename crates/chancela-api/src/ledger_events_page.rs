use chancela_ledger::{ChainId, Event};
use chancela_store::{LedgerEventPageQuery, LedgerEventUpperBound};

use crate::AppState;
use crate::error::ApiError;
use crate::ledger_filter::{LedgerEventFilters, UpperBound};

pub(crate) struct LedgerEventsSelectorQuery<'a> {
    pub(crate) before_seq: Option<u64>,
    pub(crate) limit: usize,
    pub(crate) chain: Option<ChainId>,
    pub(crate) filters: &'a LedgerEventFilters,
}

pub(crate) struct LedgerEventsSelection {
    pub(crate) events: Vec<Event>,
    pub(crate) next_cursor: Option<u64>,
    pub(crate) has_more: bool,
    pub(crate) limit: usize,
}

pub(crate) async fn select_ledger_events_page(
    state: &AppState,
    query: LedgerEventsSelectorQuery<'_>,
) -> Result<LedgerEventsSelection, ApiError> {
    if let Some(store) = &state.store {
        let page = store
            .ledger_events_page(&store_query(&query))
            .map_err(|e| {
                ApiError::Internal(format!("failed to read persisted ledger events: {e}"))
            })?;
        return Ok(LedgerEventsSelection {
            events: page.events,
            next_cursor: page.next_cursor,
            has_more: page.has_more,
            limit: page.limit,
        });
    }

    let ledger = state.ledger.read().await;
    let mut selected = Vec::with_capacity(query.limit.saturating_add(1));
    for event in ledger.events().iter().rev() {
        if query.before_seq.is_some_and(|before| event.seq >= before) {
            continue;
        }
        if !event_in_chain(event, query.chain.as_ref()) || !query.filters.matches(event) {
            continue;
        }
        selected.push(event.clone());
        if selected.len() > query.limit {
            break;
        }
    }

    let has_more = selected.len() > query.limit;
    if has_more {
        selected.truncate(query.limit);
    }
    let next_cursor = has_more
        .then(|| selected.last().map(|event| event.seq))
        .flatten();
    Ok(LedgerEventsSelection {
        events: selected,
        next_cursor,
        has_more,
        limit: query.limit,
    })
}

fn store_query(query: &LedgerEventsSelectorQuery<'_>) -> LedgerEventPageQuery {
    let mut kinds: Vec<String> = query.filters.kinds.iter().cloned().collect();
    kinds.sort_unstable();
    LedgerEventPageQuery {
        before_seq: query.before_seq,
        limit: query.limit,
        chain: query.chain.clone(),
        q: query.filters.query.clone(),
        scope: query.filters.scope.clone(),
        kinds,
        actor: query.filters.actor.clone(),
        from: query.filters.from,
        to: query.filters.to.as_ref().map(store_upper_bound),
    }
}

fn store_upper_bound(bound: &UpperBound) -> LedgerEventUpperBound {
    match bound {
        UpperBound::Inclusive(to) => LedgerEventUpperBound::Inclusive(*to),
        UpperBound::Exclusive(to) => LedgerEventUpperBound::Exclusive(*to),
    }
}

fn event_in_chain(event: &Event, chain: Option<&ChainId>) -> bool {
    match chain {
        None | Some(ChainId::Global) => true,
        Some(chain) => event.links.iter().any(|link| &link.chain == chain),
    }
}
