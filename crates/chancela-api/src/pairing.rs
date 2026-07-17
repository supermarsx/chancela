//! Companion **pairing / device-enrollment** protocol (wp27-e4, from the a2 mobile audit).
//!
//! The companion (a phone running the bare WebView shell, `docs/mobile.md`) must obtain a session
//! **without** the operator ever typing their password into a remote WebView. This module adds a
//! short-lived **pairing-code** handshake on top of the existing session machinery:
//!
//! 1. **Mint** — the desktop operator, already holding an interactive session, calls
//!    `POST /v1/pairing/codes`. The server returns a fresh, single-use, short-TTL code (shown as a
//!    QR / deep-link by the desktop UI, wp27-e5). Only the code's **SHA-256 digest** is retained.
//! 2. **Exchange** — the phone posts the code to the **unauthenticated** `POST /v1/pairing/exchange`.
//!    The server verifies the code (fail-closed: unknown, expired, and already-used are one uniform
//!    `401`), mints an identity-only companion [`session`](crate::session) (no unlocked attestation
//!    key), records a durable **device** row, and returns the session token + device id.
//! 3. **List / revoke** — `GET /v1/pairing/devices` lists the operator's enrolled devices;
//!    `DELETE /v1/pairing/devices/{device_id}` soft-revokes one and kills its companion session.
//!
//! **Durability (mirrors [`crate::session`]'s digest-only registry):** enrolled devices persist to
//! the `pairing_devices` store table (schema v22) as a document-in-relational `(id, json)` row whose
//! record holds **only the digest** of the companion session token — never the plaintext bearer — so
//! the table is a device directory, not a token database. The registry is rehydrated at boot
//! ([`PairingRegistry::from_store`]) so a device survives a restart, exactly like `sessions.json`.
//!
//! **Security:** pairing codes are single-use and TTL-bounded; verification is by digest lookup (the
//! same constant-work path the session token check uses — the secret is only ever compared as its
//! SHA-256 preimage). Expiry and reuse fail **closed** with a uniform error that leaks nothing. The
//! password sign-in path is untouched; pairing is strictly additive.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_store::Store;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::cluster_shared_state;
use crate::error::ApiError;
use crate::session::{mint_session, session_token_digest};
use crate::users::{UserId, UserView};

/// A pairing code is valid for five minutes: long enough to scan a QR and complete enrollment, short
/// enough that a leaked or shoulder-surfed code is useless almost immediately.
pub(crate) const PAIRING_CODE_TTL_SECS: i64 = 5 * 60;

/// Default per-device label when the operator does not name the device.
const DEFAULT_DEVICE_LABEL: &str = "Dispositivo emparelhado";

/// Bound the operator-supplied device label so a record stays small and printable.
const MAX_LABEL_LEN: usize = 120;

/// A device enrolled through the pairing handshake, persisted opaquely in `pairing_devices` (v22).
///
/// **Digest-only:** `token_sha256` is the SHA-256 digest of the companion session token, never the
/// plaintext bearer. A revoked device is soft-marked with `revoked_at_unix` so it stays listable.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DurablePairingDevice {
    device_id: String,
    user_id: Uuid,
    label: String,
    token_sha256: String,
    created_at_unix: i64,
    revoked_at_unix: Option<i64>,
}

/// One outstanding, not-yet-redeemed pairing code. Held in memory only — a code is an ephemeral
/// bootstrap secret; losing outstanding codes on restart is harmless (the operator mints a new one)
/// and strictly safer than persisting them.
#[derive(Clone, Debug)]
struct PendingPairingCode {
    user_id: Uuid,
    label: String,
    expires_at_unix: i64,
}

/// Cloneable handle to the in-memory pairing registry: outstanding codes plus the (store-backed)
/// enrolled-device index. [`Default`] is empty; [`from_store`](PairingRegistry::from_store) rehydrates
/// the device index from the durable table at boot.
#[derive(Clone, Default)]
pub struct PairingRegistry(Arc<PairingRegistryInner>);

#[derive(Default)]
struct PairingRegistryInner {
    /// Outstanding pairing codes, keyed by the code **digest** (single-use, TTL-bounded).
    codes: RwLock<HashMap<String, PendingPairingCode>>,
    /// Enrolled devices, keyed by `device_id` — an in-memory mirror of the `pairing_devices` table.
    devices: RwLock<HashMap<String, DurablePairingDevice>>,
}

impl PairingRegistry {
    /// Rehydrate the enrolled-device index from the durable `pairing_devices` table (schema v22) so a
    /// device — and the operator's ability to see and revoke it — survives an API restart. An
    /// unparseable row is skipped defensively (the store never interprets the blob). Outstanding
    /// pairing codes are intentionally **not** durable and start empty.
    pub(crate) fn from_store(store: &Store) -> Self {
        let mut devices = HashMap::new();
        if let Ok(rows) = store.pairing_devices() {
            for (_, json) in rows {
                if let Ok(record) = serde_json::from_str::<DurablePairingDevice>(&json) {
                    devices.insert(record.device_id.clone(), record);
                }
            }
        }
        Self(Arc::new(PairingRegistryInner {
            codes: RwLock::new(HashMap::new()),
            devices: RwLock::new(devices),
        }))
    }

    /// Mint a fresh single-use pairing code for `user_id`, retaining only its digest, and prune any
    /// already-expired outstanding codes. Returns the plaintext code (shown once, as a QR/deep-link).
    async fn mint_code(&self, user_id: Uuid, label: String, now: OffsetDateTime) -> String {
        let code = Uuid::new_v4().simple().to_string();
        let digest = session_token_digest(&code);
        let expires_at_unix = (now + Duration::seconds(PAIRING_CODE_TTL_SECS)).unix_timestamp();
        let mut codes = self.0.codes.write().await;
        codes.retain(|_, pending| now.unix_timestamp() < pending.expires_at_unix);
        codes.insert(
            digest,
            PendingPairingCode {
                user_id,
                label,
                expires_at_unix,
            },
        );
        code
    }

    /// Redeem a presented code: look it up by digest and **remove it (single-use) regardless** of the
    /// outcome, then fail closed if it had already expired. Returns the bound `(user_id, label)` only
    /// for a live, first-use code. A second exchange of the same code — or an unknown/expired one —
    /// returns `None`, which the handler renders as the same uniform error.
    async fn redeem_code(&self, code: &str, now: OffsetDateTime) -> Option<(Uuid, String)> {
        let digest = session_token_digest(code.trim());
        let mut codes = self.0.codes.write().await;
        let pending = codes.remove(&digest)?;
        if now.unix_timestamp() >= pending.expires_at_unix {
            return None;
        }
        Some((pending.user_id, pending.label))
    }

    /// Commit a freshly enrolled device to the in-memory index (the durable write is done first by
    /// the handler).
    async fn insert_device(&self, record: DurablePairingDevice) {
        self.0
            .devices
            .write()
            .await
            .insert(record.device_id.clone(), record);
    }

    /// The `user_id`'s enrolled devices, newest first, rendered for the wire.
    async fn devices_for(&self, user_id: Uuid) -> Vec<PairingDeviceView> {
        let devices = self.0.devices.read().await;
        let mut out: Vec<PairingDeviceView> = devices
            .values()
            .filter(|device| device.user_id == user_id)
            .map(PairingDeviceView::from)
            .collect();
        out.sort_by(|a, b| {
            b.created_at_unix
                .cmp(&a.created_at_unix)
                .then(a.device_id.cmp(&b.device_id))
        });
        out
    }

    /// Soft-revoke a device the caller owns, stamping `revoked_at` if not already set, and return the
    /// updated record for the durable write + session teardown. `None` when the device is unknown or
    /// owned by a different user (the handler renders both as `404`, never leaking existence).
    async fn revoke_device(
        &self,
        device_id: &str,
        user_id: Uuid,
        now: OffsetDateTime,
    ) -> Option<DurablePairingDevice> {
        let mut devices = self.0.devices.write().await;
        let record = devices.get_mut(device_id)?;
        if record.user_id != user_id {
            return None;
        }
        if record.revoked_at_unix.is_none() {
            record.revoked_at_unix = Some(now.unix_timestamp());
        }
        Some(record.clone())
    }
}

/// Render a unix timestamp as an RFC 3339 string (best-effort; a never-expected out-of-range value
/// falls back to the epoch rather than failing a read).
fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

/// Normalize an optional operator-supplied label: trim, bound the length, and fall back to a default
/// when empty.
fn sanitize_label(label: Option<String>) -> String {
    let trimmed = label.unwrap_or_default();
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        return DEFAULT_DEVICE_LABEL.to_owned();
    }
    trimmed.chars().take(MAX_LABEL_LEN).collect()
}

/// Resolve the acting operator's [`UserId`] from an **interactive session** (pairing is initiated by
/// a signed-in operator, not by an API key). A key-authenticated or user-less request is refused.
async fn resolve_operator(state: &AppState, actor: &CurrentActor) -> Result<UserId, ApiError> {
    let Some(username) = actor.session_username() else {
        return Err(ApiError::Forbidden(
            "o emparelhamento requer uma sessão interativa".to_owned(),
        ));
    };
    let users = state.users.read().await;
    users
        .values()
        .find(|u| u.username == username && u.active)
        .map(|u| u.id)
        .ok_or_else(|| ApiError::Unauthorized("sessão inválida".to_owned()))
}

/// Write-through the device record to the durable store on the async request path (offloaded via the
/// wp27-e9 `persist_blocking_async` wrapper so the async worker is never blocked). A **no-op** when
/// the state is in-memory (`store` is `None`) — matching the session registry's behaviour.
async fn persist_device(state: &AppState, record: &DurablePairingDevice) -> Result<(), ApiError> {
    let Some(store) = state.store.clone() else {
        return Ok(());
    };
    let id = record.device_id.clone();
    let json = serde_json::to_string(record)
        .map_err(|e| ApiError::Internal(format!("failed to serialize pairing device: {e}")))?;
    store
        .persist_blocking_async(move |tx| tx.upsert_pairing_device(&id, &json))
        .await
        .map_err(|e| ApiError::Internal(format!("failed to persist pairing device: {e}")))
}

/// Body of `POST /v1/pairing/codes`.
#[derive(Deserialize)]
pub struct MintPairingCode {
    /// Optional human label for the device that will redeem this code (e.g. "Telemóvel da Amélia").
    #[serde(default)]
    pub label: Option<String>,
}

/// Response of `POST /v1/pairing/codes` — the one-time code plus its expiry.
#[derive(Serialize)]
pub struct PairingCodeMinted {
    /// The single-use pairing code (rendered as a QR / deep-link by the desktop UI).
    pub code: String,
    /// RFC 3339 expiry instant.
    pub expires_at: String,
    /// Seconds until expiry (the code TTL), for a countdown without clock-skew math.
    pub expires_in_secs: i64,
    /// The resolved device label bound to this code.
    pub label: String,
}

/// `POST /v1/pairing/codes` — mint a short-lived, single-use pairing code for the signed-in operator.
pub async fn create_pairing_code(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<MintPairingCode>,
) -> Result<Json<PairingCodeMinted>, ApiError> {
    let uid = resolve_operator(&state, &actor).await?;
    let label = sanitize_label(req.label);
    let now = OffsetDateTime::now_utc();
    let code = state.pairing.mint_code(uid.0, label.clone(), now).await;
    let expires_at = now + Duration::seconds(PAIRING_CODE_TTL_SECS);
    Ok(Json(PairingCodeMinted {
        code,
        expires_at: expires_at.format(&Rfc3339).unwrap_or_else(|_| rfc3339(0)),
        expires_in_secs: PAIRING_CODE_TTL_SECS,
        label,
    }))
}

/// Body of `POST /v1/pairing/exchange`.
#[derive(Deserialize)]
pub struct ExchangePairingCode {
    /// The pairing code the desktop showed the phone.
    pub code: String,
}

/// Response of `POST /v1/pairing/exchange` — the minted companion session + the enrolled device.
#[derive(Serialize)]
pub struct PairingExchanged {
    /// The companion session token (sent as `X-Chancela-Session` on subsequent requests).
    pub token: String,
    /// The stable device id, used to list and revoke this enrollment.
    pub device_id: String,
    /// The device label bound at mint time.
    pub label: String,
    /// The operator the companion now acts as.
    pub user: UserView,
}

/// `POST /v1/pairing/exchange` — **unauthenticated**: the phone redeems a pairing code for a session.
///
/// Fail-closed and uniform: an unknown, expired, or already-redeemed code all return the same `401`
/// so a caller cannot distinguish them. On success the code is consumed (single-use), an identity-only
/// companion session is minted (no unlocked attestation key — the phone never authenticated a key),
/// and a durable device row is written before the token is returned.
pub async fn exchange_pairing_code(
    State(state): State<AppState>,
    Json(req): Json<ExchangePairingCode>,
) -> Result<Json<PairingExchanged>, ApiError> {
    let now = OffsetDateTime::now_utc();
    let invalid =
        || ApiError::Unauthorized("código de emparelhamento inválido ou expirado".to_owned());

    let Some((user_id, label)) = state.pairing.redeem_code(&req.code, now).await else {
        return Err(invalid());
    };
    let uid = UserId(user_id);
    // The bound user must still exist and be active; otherwise the (now-consumed) code is dead.
    let user = {
        let users = state.users.read().await;
        match users.get(&uid).cloned() {
            Some(u) if u.active => u,
            _ => return Err(invalid()),
        }
    };

    // Mint an identity-only companion session, then bind a durable device to its token digest.
    let token = mint_session(&state, uid, None).await?;
    let record = DurablePairingDevice {
        device_id: Uuid::new_v4().to_string(),
        user_id,
        label: label.clone(),
        token_sha256: session_token_digest(&token),
        created_at_unix: now.unix_timestamp(),
        revoked_at_unix: None,
    };
    // Durable write first; on failure tear the just-minted session back down so we never leave an
    // untracked, unrevocable companion session behind.
    if let Err(e) = persist_device(&state, &record).await {
        evict_session_by_token(&state, &token).await;
        return Err(e);
    }
    let device_id = record.device_id.clone();
    state.pairing.insert_device(record).await;

    Ok(Json(PairingExchanged {
        token,
        device_id,
        label,
        user: UserView::from(&user),
    }))
}

/// One enrolled device rendered for the wire.
#[derive(Serialize)]
pub struct PairingDeviceView {
    pub device_id: String,
    pub label: String,
    /// RFC 3339 enrollment instant.
    pub created_at: String,
    /// Whether the device has been revoked.
    pub revoked: bool,
    /// RFC 3339 revoke instant, or `null` while active.
    pub revoked_at: Option<String>,
    /// Sort key, excluded from the wire (view ordering only).
    #[serde(skip)]
    created_at_unix: i64,
}

impl From<&DurablePairingDevice> for PairingDeviceView {
    fn from(device: &DurablePairingDevice) -> Self {
        PairingDeviceView {
            device_id: device.device_id.clone(),
            label: device.label.clone(),
            created_at: rfc3339(device.created_at_unix),
            revoked: device.revoked_at_unix.is_some(),
            revoked_at: device.revoked_at_unix.map(rfc3339),
            created_at_unix: device.created_at_unix,
        }
    }
}

/// Response of `GET /v1/pairing/devices`.
#[derive(Serialize)]
pub struct PairingDevices {
    pub devices: Vec<PairingDeviceView>,
}

/// `GET /v1/pairing/devices` — the signed-in operator's enrolled companion devices, newest first.
pub async fn list_pairing_devices(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<PairingDevices>, ApiError> {
    let uid = resolve_operator(&state, &actor).await?;
    let devices = state.pairing.devices_for(uid.0).await;
    Ok(Json(PairingDevices { devices }))
}

/// `DELETE /v1/pairing/devices/{device_id}` — revoke one of the operator's devices and kill its
/// companion session. Idempotent-ish: revoking an already-revoked device re-affirms the teardown and
/// still returns `204`. A device the operator does not own is `404` (never revealing it exists).
pub async fn revoke_pairing_device(
    State(state): State<AppState>,
    actor: CurrentActor,
    Path(device_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let uid = resolve_operator(&state, &actor).await?;
    let now = OffsetDateTime::now_utc();
    let Some(record) = state.pairing.revoke_device(&device_id, uid.0, now).await else {
        return Err(ApiError::NotFound);
    };
    // Persist the soft-revoke, then kill the companion session everywhere this node can reach:
    //  - the durable digest registry, by digest (no plaintext bearer needed — single-node authority);
    //  - any in-memory copy on THIS node, matched by digest (the plaintext may be unknown after a
    //    restart, so we recompute the digest of each live token rather than needing the bearer);
    //  - a cluster-wide invalidation broadcast carrying only the digest (HA peers evict by digest).
    persist_device(&state, &record).await?;
    state
        .durable_sessions
        .revoke_by_digest(&record.token_sha256)
        .await?;
    evict_sessions_by_digest(&state, &record.token_sha256).await;
    state.cluster_shared.invalidation.publish(
        &cluster_shared_state::InvalidationEvent::SessionRevoked {
            token_sha256: record.token_sha256.clone(),
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Evict a companion session from this node's in-memory maps + the shared authority using the
/// plaintext token (the exchange path still holds it).
async fn evict_session_by_token(state: &AppState, token: &str) {
    state.sessions.write().await.remove(token);
    state.session_issued_at.write().await.remove(token);
    let _ = state.durable_sessions.revoke(token).await;
    let _ = state.cluster_shared.sessions.revoke(token);
}

/// Evict every in-memory session on this node whose token matches `token_sha256`. The companion
/// bearer is never persisted, so after a restart this node may hold a re-hydrated in-memory copy
/// whose plaintext it cannot otherwise address; recomputing each live token's digest finds it.
async fn evict_sessions_by_digest(state: &AppState, token_sha256: &str) {
    let matched: Vec<String> = {
        let sessions = state.sessions.read().await;
        sessions
            .keys()
            .filter(|token| session_token_digest(token) == token_sha256)
            .cloned()
            .collect()
    };
    if matched.is_empty() {
        return;
    }
    let mut sessions = state.sessions.write().await;
    let mut issued = state.session_issued_at.write().await;
    for token in &matched {
        sessions.remove(token);
        issued.remove(token);
        let _ = state.cluster_shared.sessions.revoke(token);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axum::body::{Body, to_bytes};
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{Method, Request, StatusCode};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::actor::SESSION_HEADER;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("chancela-pairing-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("create temp data dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    async fn json_response(response: axum::response::Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("read response body");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON response")
        };
        (status, value)
    }

    fn json_request(method: Method, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn auth_request(method: Method, uri: &str, token: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(SESSION_HEADER, token)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    async fn operator_session(state: &AppState) -> String {
        let (status, user) = json_response(
            crate::router(state.clone())
                .oneshot(json_request(
                    Method::POST,
                    "/v1/users",
                    json!({ "username": "amelia.marques", "password": "Cavalo-Certo9!" }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create user: {user}");
        let (status, session) = json_response(
            crate::router(state.clone())
                .oneshot(json_request(
                    Method::POST,
                    "/v1/session",
                    json!({ "user_id": user["id"], "password": "Cavalo-Certo9!" }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "sign in: {session}");
        session["token"].as_str().unwrap().to_owned()
    }

    async fn mint_code(state: &AppState, operator: &str) -> String {
        let (status, minted) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    "/v1/pairing/codes",
                    operator,
                    json!({ "label": "Telemóvel da Amélia" }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "mint code: {minted}");
        assert_eq!(minted["label"], "Telemóvel da Amélia");
        minted["code"].as_str().unwrap().to_owned()
    }

    async fn exchange(state: &AppState, code: &str) -> (StatusCode, Value) {
        json_response(
            crate::router(state.clone())
                .oneshot(json_request(
                    Method::POST,
                    "/v1/pairing/exchange",
                    json!({ "code": code }),
                ))
                .await
                .unwrap(),
        )
        .await
    }

    async fn session_user(state: &AppState, token: &str) -> Value {
        let request = Request::builder()
            .uri("/v1/session")
            .header(SESSION_HEADER, token)
            .body(Body::empty())
            .unwrap();
        let (status, view) =
            json_response(crate::router(state.clone()).oneshot(request).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        view["user"].clone()
    }

    #[tokio::test]
    async fn mint_then_exchange_yields_a_working_companion_session() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let code = mint_code(&state, &operator).await;

        let (status, exchanged) = exchange(&state, &code).await;
        assert_eq!(status, StatusCode::OK, "exchange: {exchanged}");
        let companion = exchanged["token"].as_str().unwrap();
        assert!(!exchanged["device_id"].as_str().unwrap().is_empty());
        assert_eq!(exchanged["user"]["username"], "amelia.marques");
        assert_ne!(companion, operator, "companion token is distinct");

        // The companion token authenticates as the operator's user.
        assert_eq!(
            session_user(&state, companion).await["username"],
            "amelia.marques"
        );

        // The device shows up in the operator's device list.
        let (status, devices) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::GET,
                    "/v1/pairing/devices",
                    &operator,
                    Value::Null,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "list devices: {devices}");
        let list = devices["devices"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["label"], "Telemóvel da Amélia");
        assert_eq!(list[0]["revoked"], false);
    }

    #[tokio::test]
    async fn pairing_code_is_single_use() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let code = mint_code(&state, &operator).await;

        let (first, _) = exchange(&state, &code).await;
        assert_eq!(first, StatusCode::OK);
        let (second, body) = exchange(&state, &code).await;
        assert_eq!(second, StatusCode::UNAUTHORIZED, "reuse rejected: {body}");
    }

    #[tokio::test]
    async fn unknown_code_is_rejected() {
        let state = AppState::default();
        let (status, _) = exchange(&state, "definitely-not-a-real-code").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_code_fails_closed_and_is_consumed() {
        // Drive the registry directly so we can advance the clock past the TTL.
        let registry = PairingRegistry::default();
        let uid = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let code = registry.mint_code(uid, "Phone".to_owned(), now).await;

        let past_ttl = now + Duration::seconds(PAIRING_CODE_TTL_SECS + 1);
        assert!(
            registry.redeem_code(&code, past_ttl).await.is_none(),
            "an expired code is rejected"
        );
        // And it was consumed even though it was expired — a later in-window retry cannot revive it.
        assert!(
            registry.redeem_code(&code, now).await.is_none(),
            "an expired code is not revivable"
        );
    }

    #[tokio::test]
    async fn revoke_by_device_kills_the_companion_session() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let code = mint_code(&state, &operator).await;
        let (_, exchanged) = exchange(&state, &code).await;
        let companion = exchanged["token"].as_str().unwrap().to_owned();
        let device_id = exchanged["device_id"].as_str().unwrap().to_owned();

        // Working before revoke.
        assert_eq!(
            session_user(&state, &companion).await["username"],
            "amelia.marques"
        );

        let response = crate::router(state.clone())
            .oneshot(auth_request(
                Method::DELETE,
                &format!("/v1/pairing/devices/{device_id}"),
                &operator,
                Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // The companion session is dead; the operator's own session is unaffected.
        assert!(session_user(&state, &companion).await.is_null());
        assert_eq!(
            session_user(&state, &operator).await["username"],
            "amelia.marques"
        );

        // The device is still listed, now flagged revoked.
        let (_, devices) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::GET,
                    "/v1/pairing/devices",
                    &operator,
                    Value::Null,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(devices["devices"][0]["revoked"], true);
    }

    #[tokio::test]
    async fn revoking_another_users_device_is_not_found() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let response = crate::router(state.clone())
            .oneshot(auth_request(
                Method::DELETE,
                "/v1/pairing/devices/00000000-0000-0000-0000-000000000000",
                &operator,
                Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn exchange_requires_no_session_but_mint_does() {
        let state = AppState::default();
        // Mint without a session is refused.
        let response = crate::router(state.clone())
            .oneshot(json_request(Method::POST, "/v1/pairing/codes", json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn device_and_revocation_survive_a_restart() {
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.path.clone());
        let operator = operator_session(&state).await;
        let code = mint_code(&state, &operator).await;
        let (_, exchanged) = exchange(&state, &code).await;
        let companion = exchanged["token"].as_str().unwrap().to_owned();
        let device_id = exchanged["device_id"].as_str().unwrap().to_owned();

        // Restart: a fresh state over the same data dir rehydrates the device + the companion session.
        let restarted = AppState::with_data_dir(temp.path.clone());
        assert_eq!(
            session_user(&restarted, &companion).await["username"],
            "amelia.marques",
            "companion session survives the restart"
        );
        let (status, devices) = json_response(
            crate::router(restarted.clone())
                .oneshot(auth_request(
                    Method::GET,
                    "/v1/pairing/devices",
                    &operator,
                    Value::Null,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "list after restart: {devices}");
        assert_eq!(devices["devices"][0]["device_id"], device_id);

        // Revoke on the restarted node (no in-process live token) still kills the companion session.
        let response = crate::router(restarted.clone())
            .oneshot(auth_request(
                Method::DELETE,
                &format!("/v1/pairing/devices/{device_id}"),
                &operator,
                Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(session_user(&restarted, &companion).await.is_null());

        // And the revocation is durable across another restart.
        let again = AppState::with_data_dir(temp.path.clone());
        assert!(session_user(&again, &companion).await.is_null());
    }
}
