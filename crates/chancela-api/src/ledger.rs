//! Ledger endpoints (contract §2.6): the event feed and the chain-verify probe, plus the audit
//! attestation join + per-event verify (plan t29 §4.6).

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Serialize;

use crate::AppState;
use crate::attestation::{self, Attestation};
use crate::dto::{AttestationSummary, LedgerEventView, LedgerQuery};
use crate::error::ApiError;

/// `GET /v1/ledger/events?scope=&limit=` — events in append order, optionally filtered by a
/// `scope` substring and trimmed to the last `limit`. Each event carries its `attestation`
/// summary (joined from the in-memory sidecar by `seq`), or `null`.
pub async fn list_ledger_events(
    State(state): State<AppState>,
    Query(q): Query<LedgerQuery>,
) -> Json<Vec<LedgerEventView>> {
    let ledger = state.ledger.read().await;
    let attestations = state.attestations.read().await;
    let mut events: Vec<&_> = ledger.events().iter().collect();
    if let Some(scope) = &q.scope {
        events.retain(|e| e.scope.contains(scope.as_str()));
    }
    if let Some(limit) = q.limit {
        let start = events.len().saturating_sub(limit);
        events.drain(..start);
    }
    Json(
        events
            .into_iter()
            .map(|e| {
                let mut view = LedgerEventView::from(e);
                view.attestation = attestations.get(&e.seq).map(AttestationSummary::from);
                view
            })
            .collect(),
    )
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
pub async fn verify_ledger(State(state): State<AppState>) -> Json<VerifyResponse> {
    let ledger = state.ledger.read().await;
    match ledger.verify() {
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
    }
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
) -> Result<Json<AttestationVerifyResponse>, ApiError> {
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
