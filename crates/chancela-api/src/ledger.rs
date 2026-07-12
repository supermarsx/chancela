//! Ledger endpoints (contract §2.6): the event feed and the chain-verify probe, plus the audit
//! attestation join + per-event verify (plan t29 §4.6).

use std::str::FromStr;

use axum::Json;
use axum::extract::{Path, Query, State};
use chancela_authz::{Permission, Scope};
use chancela_ledger::ChainId;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::attestation::{self, Attestation};
use crate::authz::require_permission;
use crate::dto::{AttestationSummary, LedgerEventView, LedgerQuery};
use crate::error::ApiError;
use crate::ledger_events_page::{LedgerEventsSelectorQuery, select_ledger_events_page};
use crate::ledger_filter::{LedgerEventFilters, normalized_page_limit};

/// Default and maximum number of events returned by `GET /v1/ledger/events?limit=` (t41 L3).
const DEFAULT_LEDGER_LIMIT: usize = 100;
const MAX_LEDGER_LIMIT: usize = 1000;

/// `GET /v1/ledger/events?chain=&scope=&limit=` — events in append order, optionally narrowed to a
/// chain, filtered by a `scope` substring, and trimmed to the last `limit` (clamped to max 1000,
/// default 100 — t41 L3). Each event carries its chain membership and `attestation` summary (joined
/// from the in-memory sidecar by `seq`).
pub async fn list_ledger_events(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(q): Query<LedgerQuery>,
) -> Result<Json<Vec<LedgerEventView>>, ApiError> {
    // RBAC (t64-E3): the audit feed is `ledger.read` at Global.
    require_permission(&state, &actor, Permission::LedgerRead, Scope::Global).await?;
    let chain = q
        .chain
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(parse_chain)
        .transpose()?;
    let filters = LedgerEventFilters::from_parts(
        q.q,
        q.scope,
        &q.kind,
        q.actor,
        q.from.as_deref(),
        q.to.as_deref(),
    )?;
    let ledger = state.ledger.read().await;
    let attestations = state.attestations.read().await;
    let mut events: Vec<&_> = match &chain {
        Some(chain) => ledger.events_in_chain(chain),
        None => ledger.events().iter().collect(),
    };
    events.retain(|e| filters.matches(e));
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LEDGER_LIMIT)
        .min(MAX_LEDGER_LIMIT);
    let start = events.len().saturating_sub(limit);
    events.drain(..start);
    Ok(Json(
        events
            .into_iter()
            .map(|e| {
                let mut view = LedgerEventView::from(e);
                view.attestation = attestations.get(&e.seq).map(AttestationSummary::from);
                view
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct LedgerPageQuery {
    pub q: Option<String>,
    pub chain: Option<String>,
    pub scope: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::ledger_filter::deserialize_kind_query"
    )]
    pub kind: Vec<String>,
    pub actor: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub before_seq: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct LedgerEventsPage {
    pub events: Vec<LedgerEventView>,
    pub next_cursor: Option<u64>,
    pub has_more: bool,
    pub limit: usize,
}

/// `GET /v1/ledger/events/page?before_seq=&limit=` — newest-first ledger page.
///
/// The cursor is a global `seq` boundary: when `next_cursor` is `Some(n)`, request
/// `before_seq=n` to fetch the next older page. The displayed order is newest-first, but each
/// event still carries the original global `seq`, `prev_hash`, and `hash` values; the hash chain
/// itself remains append-order.
pub async fn list_ledger_events_page(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(q): Query<LedgerPageQuery>,
) -> Result<Json<LedgerEventsPage>, ApiError> {
    require_permission(&state, &actor, Permission::LedgerRead, Scope::Global).await?;
    let chain = q
        .chain
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(parse_chain)
        .transpose()?;
    let filters = LedgerEventFilters::from_parts(
        q.q,
        q.scope,
        &q.kind,
        q.actor,
        q.from.as_deref(),
        q.to.as_deref(),
    )?;
    let limit = normalized_page_limit(q.limit);
    let page = select_ledger_events_page(
        &state,
        LedgerEventsSelectorQuery {
            before_seq: q.before_seq,
            limit,
            chain,
            filters: &filters,
        },
    )
    .await?;
    let attestations = state.attestations.read().await;
    let events = page
        .events
        .iter()
        .map(|event| {
            let mut view = LedgerEventView::from(event);
            view.attestation = attestations.get(&event.seq).map(AttestationSummary::from);
            view
        })
        .collect();

    Ok(Json(LedgerEventsPage {
        events,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
        limit: page.limit,
    }))
}

fn parse_chain(raw: &str) -> Result<ChainId, ApiError> {
    ChainId::from_str(raw).map_err(|_| {
        ApiError::Unprocessable(format!(
            "invalid chain {raw:?}; expected global, application, company:<id>, or book:<id>"
        ))
    })
}

/// Result of `GET /v1/ledger/verify`.
///
/// `valid` reflects whether the whole chain recomputes cleanly; on failure `error` carries
/// the first broken-link description and `length` is the raw event count.
#[derive(Serialize)]
pub struct VerifyResponse {
    valid: bool,
    length: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// `GET /v1/ledger/verify` — recompute the in-memory ledger's hash chain (ARC-11/12).
pub async fn verify_ledger(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<VerifyResponse>, ApiError> {
    // RBAC (t64-E3): the chain-verify probe is `ledger.read` at Global.
    require_permission(&state, &actor, Permission::LedgerRead, Scope::Global).await?;
    let ledger = state.ledger.read().await;
    Ok(match ledger.verify() {
        Ok(length) => Json(VerifyResponse {
            valid: true,
            length,
            error: None,
        }),
        Err(e) => Json(VerifyResponse {
            valid: false,
            length: ledger.len() as u64,
            error: Some(e.to_string()),
        }),
    })
}

/// Response of `GET /v1/ledger/attestations/{seq}` (plan t29 §4.6): the full attestation plus the
/// server's re-verification verdict.
#[derive(Serialize)]
pub struct AttestationVerifyResponse {
    pub attestation: Attestation,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `GET /v1/ledger/attestations/{seq}` — fetch one attestation and re-verify it server-side
/// (plan t29 §4.6). `404` when no attestation exists for that seq.
///
/// Two independent checks must both hold for `valid:true`: (1) the signature verifies over the
/// stored `event_hash` using the signing key's public key (looked up by fingerprint across users);
/// (2) that `event_hash` still equals the live ledger event's hash at `seq` (binding the
/// attestation to the actual chain position). A rotated/removed key, a bad signature, or a
/// tampered/rebuilt chain each yield `valid:false` with a `reason`.
pub async fn get_attestation(
    State(state): State<AppState>,
    Path(seq): Path<u64>,
    actor: CurrentActor,
) -> Result<Json<AttestationVerifyResponse>, ApiError> {
    // RBAC (t64-E3): reading an attestation is `ledger.read` at Global.
    require_permission(&state, &actor, Permission::LedgerRead, Scope::Global).await?;
    let attestation = {
        let attestations = state.attestations.read().await;
        attestations.get(&seq).cloned().ok_or(ApiError::NotFound)?
    };

    // The live chain hash at this seq (if the event still exists).
    let live_hash = {
        let ledger = state.ledger.read().await;
        ledger
            .events()
            .get(seq as usize)
            .map(|e| crate::hex::hex(&e.hash))
    };

    // The signing key's public bytes, found by fingerprint across users' attestation keys.
    let pubkey = {
        let users = state.users.read().await;
        users.values().find_map(|u| {
            u.attestation_key
                .as_ref()
                .filter(|k| k.fingerprint == attestation.fingerprint)
                .and_then(|k| k.public_key_bytes())
        })
    };

    let (valid, reason) = evaluate(&attestation, live_hash.as_deref(), pubkey.as_deref());
    Ok(Json(AttestationVerifyResponse {
        attestation,
        valid,
        reason,
    }))
}

/// Decide the verdict for an attestation given the live chain hash and the recorded key.
fn evaluate(
    att: &Attestation,
    live_hash: Option<&str>,
    pubkey: Option<&[u8]>,
) -> (bool, Option<String>) {
    let Some(pubkey) = pubkey else {
        return (
            false,
            Some("signing key not found — it was rotated or removed".to_owned()),
        );
    };
    if !attestation::verify_signature(att, pubkey) {
        return (
            false,
            Some("signature does not verify against the recorded key".to_owned()),
        );
    }
    match live_hash {
        None => (false, Some("no ledger event exists at this seq".to_owned())),
        Some(h) if h != att.event_hash => (
            false,
            Some(
                "event hash does not match the live ledger — the chain was tampered or rebuilt"
                    .to_owned(),
            ),
        ),
        Some(_) => (true, None),
    }
}
