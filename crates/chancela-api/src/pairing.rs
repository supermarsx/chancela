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
//!    `401`), **requires a confirmation** (below), mints an identity-only companion
//!    [`session`](crate::session) (no unlocked attestation key), records a durable **device** row,
//!    and returns the session token + device id.
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
//!
//! ## Confirming the exchange (t70)
//!
//! A live pairing code is not on its own enough to enrol a device. The exchange additionally
//! requires **one** proof from the operator the code is bound to — see
//! [`crate::confirmation::PairingConfirmationMethod`] for the accepted set and
//! [`require_pairing_confirmation`](crate::confirmation::require_pairing_confirmation) for the gate.
//!
//! **This does not undo the password-free rationale at the top of this file.** The password is one
//! accepted proof, never the only one: a TOTP token proves the same operator without any reusable
//! secret reaching the device, and a deployment that wants that guarantee absolutely can narrow
//! `auth.device_pairing.accepted` so a password is not accepted here at all. What the confirmation
//! closes is the gap where possession of a code — shoulder-surfed from a QR, or photographed off an
//! unattended screen — was by itself a session as the operator.
//!
//! **A failed confirmation burns the code**, because [`PairingRegistry::redeem_code`] consumes it
//! before the proof is checked. That is deliberate and is not a rough edge to smooth: leaving the
//! code live for the rest of its five minutes would turn a six-digit TOTP into an unlimited online
//! guessing target. One attempt per code; a mistyped proof costs the operator a fresh QR.

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
use crate::confirmation::{
    ConfirmationAction, ConfirmationProof, PairingConfirmationMethod, PairingConfirmationProof,
    require_confirmation, require_pairing_confirmation,
};
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
///
/// # No `deny_unknown_fields`, deliberately (t70)
///
/// It was there, and it was a **deploy-rollback hazard**. The attribute is symmetric, but
/// `#[serde(default)]` only defends one direction: it lets a NEW binary read OLD rows. The other
/// direction had nothing. An OLD binary reading rows written by a NEWER one would hit the unknown
/// field, fail to parse, and be dropped by the skip in [`PairingRegistry::from_store`] — silently
/// emptying every operator's device list and taking their ability to revoke those devices with it.
/// That fires on the *next* field anyone adds here, which for a device directory is a matter of
/// time.
///
/// What the attribute bought was strictness against a key this code never writes: the only writer
/// is this struct's own `serde_json::to_string`, and the store treats the blob as opaque. So it
/// defended against hand-edited or corrupted rows, and charged silent data loss on every rollback
/// after a schema change. That is the wrong trade for a row whose whole job is to remain
/// revocable.
///
/// Both directions are now pinned by tests, because a compatibility property with no test is one
/// the next person deletes by accident.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DurablePairingDevice {
    device_id: String,
    user_id: Uuid,
    label: String,
    token_sha256: String,
    created_at_unix: i64,
    revoked_at_unix: Option<i64>,
    /// Which proof confirmed this enrollment (t70). `None` **only** for a row written before the
    /// confirmation existed — `#[serde(default)]` is what keeps those rows parseable, and it
    /// matters more than it looks: [`PairingRegistry::from_store`] *skips* a row it cannot
    /// deserialize, so without the default an upgrade would silently drop every already-enrolled
    /// device out of the operator's list, taking their ability to revoke it with them.
    #[serde(default)]
    confirmed_by: Option<PairingConfirmationMethod>,
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
            for (id, json) in rows {
                match serde_json::from_str::<DurablePairingDevice>(&json) {
                    Ok(record) => {
                        devices.insert(record.device_id.clone(), record);
                    }
                    // **The skip is the dangerous part, so it is no longer silent.** A dropped row
                    // is a device the operator can no longer see and therefore can no longer
                    // revoke — a security-relevant loss that used to look exactly like "there were
                    // no devices". The row id is safe to log: it is the table key, not the token
                    // digest and not the label. The blob itself is never logged.
                    Err(error) => tracing::warn!(
                        device_row = %id,
                        ?error,
                        "a pairing_devices row could not be parsed and was skipped; the device it \
                         describes will not be listable or revocable until this is resolved"
                    ),
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

    /// Drop an outstanding code without redeeming it. Used when a mint has to be unwound after the
    /// code was already minted — the operator never saw it, so leaving it live would be a live
    /// credential nobody knows exists.
    async fn discard_code(&self, code: &str) {
        let digest = session_token_digest(code.trim());
        self.0.codes.write().await.remove(&digest);
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
///
/// Deliberately **no `Debug`**: [`ConfirmationProof`] carries a plaintext password.
#[derive(Deserialize)]
pub struct MintPairingCode {
    /// Optional human label for the device that will redeem this code (e.g. "Telemóvel da Amélia").
    #[serde(default)]
    pub label: Option<String>,
    /// The step-up proof for [`ConfirmationAction::DevicePairing`]. `#[serde(default)]`, so a body
    /// that omits it deserialises to an empty proof and is refused.
    #[serde(default)]
    pub confirmation: ConfirmationProof,
    /// Ask for a confirmation code to be mailed to the operator's registered address, for the
    /// device to type back at the exchange. Off by default: mail is only sent when the operator
    /// says they intend to use it, so an instance whose operators all use TOTP sends none.
    #[serde(default)]
    pub email_confirmation_code: bool,
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
    /// The proofs this deployment accepts to confirm the exchange, as stable identifiers. The
    /// device redeeming the code is unauthenticated and so cannot read `GET /v1/confirmation-policy`
    /// itself; the desktop, which is signed in, learns the accepted set here and tells the operator
    /// what they are about to be asked for. Not a secret — knowing that an instance accepts a TOTP
    /// code tells an attacker nothing they could not learn by trying.
    pub accepted_confirmation_methods: Vec<&'static str>,
    /// Whether a confirmation code was mailed for this pairing code. Only ever `true` after the
    /// relay accepted the message — a failed send is an error, never a `false` the operator has to
    /// notice.
    pub emailed_code_sent: bool,
}

/// `POST /v1/pairing/codes` — mint a short-lived, single-use pairing code for the signed-in operator.
///
/// **Gated on [`ConfirmationAction::DevicePairing`]**, whose floor (`ConfirmWithReauth`) the registry
/// has declared since t56-e0 with nothing enforcing it: `require_confirmation` had exactly two call
/// sites in the workspace, both in `cmd_test_signature.rs`. Until this call site existed the floor
/// was a guarantee that lived only in the settings model — the registry's own comment says minting
/// "enrols a new device as this operator, so an unattended signed-in browser must not be one click
/// from it", and an unattended signed-in browser was precisely one click from it.
///
/// This is the *mint* gate and it is not the same proof as the *exchange* gate below. They defend
/// different moments and are deliberately independent: this one asks the desktop operator, who
/// already holds a session, to re-prove themselves before a code exists at all; the exchange asks
/// whoever holds the code to prove they are that operator before a device is enrolled. Neither
/// substitutes for the other, and the exchange has no equivalent of `require_step_up`'s
/// credential-less exemption.
pub async fn create_pairing_code(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: crate::actor::CurrentAttestor,
    Json(req): Json<MintPairingCode>,
) -> Result<Json<PairingCodeMinted>, ApiError> {
    let uid = resolve_operator(&state, &actor).await?;
    require_confirmation(
        &state,
        &actor,
        ConfirmationAction::DevicePairing,
        &req.confirmation,
    )
    .await?;
    let label = sanitize_label(req.label);
    let now = OffsetDateTime::now_utc();
    let accepted = {
        let settings = state.settings.read().await;
        settings.auth.device_pairing.accepted.clone()
    };

    // Everything that can refuse runs BEFORE the pairing code is minted, so a refusal here does not
    // leave a live code behind that the operator was never told about.
    let emailed = if req.email_confirmation_code {
        Some(prepare_emailed_code(&state, uid, &accepted).await?)
    } else {
        None
    };

    let code = state.pairing.mint_code(uid.0, label.clone(), now).await;
    let expires_at = now + Duration::seconds(PAIRING_CODE_TTL_SECS);

    if let Some(recipient) = emailed {
        // The send is fallible and its failure is reported, not swallowed: this mail *is* the
        // delivery of a confirmation method, so "code minted" while the code needed to use it sits
        // undelivered would be a success report for a state that is not one. The pairing code is
        // dropped again so the operator is not left holding one they cannot complete.
        if let Err(e) = issue_and_send_emailed_code(
            &state, &actor, &attestor, uid, &recipient, &label, now,
        )
        .await
        {
            state.pairing.discard_code(&code).await;
            return Err(e);
        }
    }

    Ok(Json(PairingCodeMinted {
        code,
        expires_at: expires_at.format(&Rfc3339).unwrap_or_else(|_| rfc3339(0)),
        expires_in_secs: PAIRING_CODE_TTL_SECS,
        label,
        accepted_confirmation_methods: accepted.iter().map(|m| m.as_str()).collect(),
        emailed_code_sent: req.email_confirmation_code,
    }))
}

/// The operator's details needed to mail them a confirmation code.
struct EmailedCodeRecipient {
    address: String,
    display_name: String,
    locale: Option<String>,
}

/// Check that mailing a confirmation code is something this deployment and this operator can
/// actually do, and resolve where it would go.
///
/// **Every refusal is loud and specific.** Silently skipping the mail — or sending it while the
/// deployment does not accept the method — would hand the operator a pairing code whose promised
/// confirmation either never arrives or would not be accepted if it did. These are configuration
/// mistakes the operator can fix, so they are told which one.
async fn prepare_emailed_code(
    state: &AppState,
    uid: UserId,
    accepted: &std::collections::BTreeSet<PairingConfirmationMethod>,
) -> Result<EmailedCodeRecipient, ApiError> {
    if !accepted.contains(&PairingConfirmationMethod::EmailedCode) {
        return Err(ApiError::Unprocessable(
            "esta instância não aceita a confirmação por código enviado por email; \
             veja auth.device_pairing.accepted"
                .to_owned(),
        ));
    }
    let users = state.users.read().await;
    let user = users.get(&uid).ok_or(ApiError::NotFound)?;

    // **The credential-less operator, re-derived now that a mailed code exists.**
    //
    // `require_step_up` deliberately passes on the session alone for an operator holding neither a
    // password nor a recovery phrase (the t69 lockout fix): a valid self session is the strongest
    // proof they can give, so demanding more would lock them out of their own instance. The mint
    // inherits that exemption on purpose — one step-up path, not two.
    //
    // While the exchange only accepted a password or a TOTP code, the exemption was contained: an
    // attacker at an unattended signed-in browser could mint a code such an operator could never
    // redeem, so the pairing simply never completed. **A mailed code removes that containment.**
    // The chain becomes mint-on-session-alone, then confirm with a code sent to the operator's
    // mailbox — and if that same unattended browser is signed into that mailbox, which on a shared
    // workstation is not a stretch, the pairing completes with no secret the operator knows. That
    // turns transient access to a logged-in screen into a durable companion session on the
    // attacker's own device, which outlives the operator locking the screen. That is an
    // escalation, not a lateral move.
    //
    // So this one feature refuses. Not the mint, and not step-up itself — narrowing either would
    // be the special-casing this lane declined, and would re-lock out the operator t69 unlocked.
    // What is refused is *mailing a code to an operator for whom the first factor is vacuous*,
    // because then the mailbox is not a second factor at all: it is the only one, reachable from
    // the same chair. An operator in this state can still pair with a TOTP code, and the honest
    // fix is for them to set a credential — which the message says.
    if crate::data::step_up_is_vacuous(
        user.password_hash.as_deref(),
        user.recovery_hash.as_deref(),
    ) {
        return Err(ApiError::Unprocessable(
            "a sua conta não tem palavra-passe nem frase de recuperação, por isso o código \
             enviado por email seria a única prova exigida para emparelhar. Defina uma \
             palavra-passe, ou confirme o emparelhamento com o código do autenticador."
                .to_owned(),
        ));
    }

    let address = user
        .email
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            ApiError::Unprocessable(
                "a sua conta não tem endereço de email; não há para onde enviar o código de \
                 confirmação"
                    .to_owned(),
            )
        })?
        .to_owned();
    Ok(EmailedCodeRecipient {
        address,
        display_name: user.display_name.clone(),
        locale: user.language.fixed().map(|l| l.as_str().to_owned()),
    })
}

/// Mint the transcribed confirmation code and mail it.
///
/// The plaintext exists in exactly two places and neither outlives this function: the outbound
/// message, and this stack frame. `AuthTokenSecret` zeroes itself on drop and the store keeps only
/// the digest, so a failed pairing leaves nothing to recover the code from.
async fn issue_and_send_emailed_code(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &crate::actor::CurrentAttestor,
    uid: UserId,
    recipient: &EmailedCodeRecipient,
    label: &str,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    use crate::auth_token::{AuthTokenPurpose, AuthTokenSubject};

    let purpose = AuthTokenPurpose::DevicePairingConfirmation;
    let (secret, _record) = state.auth_tokens.write().await.issue_transcribable(
        purpose,
        AuthTokenSubject::user(uid.0),
        purpose.default_ttl(),
        now,
    );
    crate::smtp_settings::send_and_record_pairing_code_email(
        state,
        &actor.resolve("api"),
        attestor,
        crate::smtp_settings::PairingCodeMessage {
            user_id: uid.0,
            recipient_email: &recipient.address,
            recipient_name: Some(&recipient.display_name),
            code: secret.expose(),
            expires_in_minutes: purpose.default_ttl().whole_minutes(),
            device_label: Some(label),
            locale_override: recipient.locale.as_deref(),
        },
    )
    .await
}

/// Body of `POST /v1/pairing/exchange`.
///
/// Deliberately **no `Debug`**: [`PairingConfirmationProof`] carries a plaintext password.
#[derive(Deserialize)]
pub struct ExchangePairingCode {
    /// The pairing code the desktop showed the phone.
    pub code: String,
    /// The operator's proof that they meant this. `#[serde(default)]`, so a body that omits it
    /// deserialises to an empty proof and is refused — never accepted.
    #[serde(default)]
    pub confirmation: PairingConfirmationProof,
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
    /// Which proof confirmed this enrollment, as a stable identifier. The client renders it as its
    /// own labelled line rather than folding it into a sentence.
    pub confirmed_by: &'static str,
}

/// `POST /v1/pairing/exchange` — **unauthenticated**: the phone redeems a pairing code for a session.
///
/// Fail-closed and uniform: an unknown, expired, or already-redeemed code all return the same `401`
/// so a caller cannot distinguish them. A live code additionally has to carry a confirmation the
/// bound operator can prove (`403` if it does not — see the module header). Only then is the code
/// consumed (single-use), an identity-only companion session minted (no unlocked attestation key —
/// the phone never authenticated a key), and a durable device row written before the token returns.
///
/// **Order matters and is load-bearing.** The confirmation is checked *before* anything is minted or
/// written, so an unconfirmed exchange leaves no session, no device row, and no durable state at
/// all — it does not pair. The only thing it does spend is the code itself, which
/// [`PairingRegistry::redeem_code`] consumes on any attempt by design.
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

    // The confirmation. A live code proves someone saw the desktop screen; this proves the operator
    // meant to enrol *this* device. Nothing above has written anything yet, so a refusal here is a
    // pairing that simply did not happen.
    let confirmed_by = require_pairing_confirmation(&state, &user, &req.confirmation, now).await?;

    // Mint an identity-only companion session, then bind a durable device to its token digest. A
    // paired companion carries no web device/IP origin here — the pairing device directory (wp27-e4)
    // is its own device record — so the active-sign-ins list shows it without a browser label.
    let token = mint_session(&state, uid, None, crate::session::SessionOrigin::default()).await?;
    let record = DurablePairingDevice {
        device_id: Uuid::new_v4().to_string(),
        user_id,
        label: label.clone(),
        token_sha256: session_token_digest(&token),
        created_at_unix: now.unix_timestamp(),
        revoked_at_unix: None,
        confirmed_by: Some(confirmed_by),
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
        confirmed_by: confirmed_by.as_str(),
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
    /// Which proof confirmed this enrollment, as a stable identifier — or `null` for a device
    /// enrolled before the confirmation requirement existed. The UI must render `null` as "not
    /// recorded" and **never** as a method: this field is evidence, and a device whose enrollment
    /// nobody confirmed must not read as one that somebody did.
    pub confirmed_by: Option<&'static str>,
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
            confirmed_by: device.confirmed_by.map(PairingConfirmationMethod::as_str),
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

    /// The operator's password in these tests. The exchange now needs a confirmation, and for most
    /// of these cases the password is the cheapest true one.
    const OPERATOR_PASSWORD: &str = "Cavalo-Certo9!";

    /// Create the operator and sign in, returning `(session token, user id)`.
    async fn operator_account(state: &AppState) -> (String, String) {
        let (status, user) = json_response(
            crate::router(state.clone())
                .oneshot(json_request(
                    Method::POST,
                    "/v1/users",
                    json!({ "username": "amelia.marques", "password": OPERATOR_PASSWORD }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create user: {user}");
        let user_id = user["id"].as_str().unwrap().to_owned();
        let (status, session) = json_response(
            crate::router(state.clone())
                .oneshot(json_request(
                    Method::POST,
                    "/v1/session",
                    json!({ "user_id": user["id"], "password": OPERATOR_PASSWORD }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "sign in: {session}");
        (session["token"].as_str().unwrap().to_owned(), user_id)
    }

    async fn operator_session(state: &AppState) -> String {
        operator_account(state).await.0
    }

    /// Enrol and confirm a real second factor for `user_id`, returning the base32 secret.
    ///
    /// The enrolment is confirmed with the code for the **previous** step, deliberately: confirming
    /// stores the accepted step as the replay floor, so confirming with the *current* step would
    /// leave every code this test could then present already spent. Using step `N-1` (inside the
    /// ±1 acceptance window) leaves step `N` unspent, which is what a real operator has when they
    /// pair a device some time after enrolling.
    async fn enrol_confirmed_totp(state: &AppState, token: &str, user_id: &str) -> String {
        let (status, started) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    &format!("/v1/users/{user_id}/two-factor/totp/enrol"),
                    token,
                    Value::Null,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "enrol totp: {started}");
        let secret = started["secret"].as_str().unwrap().to_owned();

        let previous_step = OffsetDateTime::now_utc().unix_timestamp() - crate::totp::STEP_SECONDS;
        let code = crate::totp::code_for_secret(&secret, previous_step).unwrap();
        let (status, confirmed) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    &format!("/v1/users/{user_id}/two-factor/totp/confirm"),
                    token,
                    json!({ "code": code }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "confirm totp: {confirmed}");
        secret
    }

    /// A live code for `secret` at the current step.
    fn live_totp_code(secret: &str) -> String {
        crate::totp::code_for_secret(secret, OffsetDateTime::now_utc().unix_timestamp()).unwrap()
    }

    /// Narrow this deployment's accepted confirmation methods.
    async fn accept_only(state: &AppState, methods: &[PairingConfirmationMethod]) {
        state
            .settings
            .write()
            .await
            .auth
            .device_pairing
            .accepted = methods.iter().copied().collect();
    }

    /// The operator's enrolled devices. The refusal tests assert on this: "did not pair" means no
    /// device row exists, not merely that the response was an error.
    async fn devices_of(state: &AppState, operator: &str) -> Vec<Value> {
        let (status, devices) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::GET,
                    "/v1/pairing/devices",
                    operator,
                    Value::Null,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "list devices: {devices}");
        devices["devices"].as_array().cloned().unwrap_or_default()
    }

    /// Mint a code, carrying the step-up proof the `DevicePairing` floor now demands.
    async fn mint_code(state: &AppState, operator: &str) -> String {
        let (status, minted) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    "/v1/pairing/codes",
                    operator,
                    json!({
                        "label": "Telemóvel da Amélia",
                        "confirmation": { "reauth": { "password": OPERATOR_PASSWORD } },
                    }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "mint code: {minted}");
        assert_eq!(minted["label"], "Telemóvel da Amélia");
        minted["code"].as_str().unwrap().to_owned()
    }

    /// Attempt a mint with an arbitrary confirmation object.
    async fn mint_with(state: &AppState, operator: &str, confirmation: Value) -> (StatusCode, Value) {
        json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    "/v1/pairing/codes",
                    operator,
                    json!({ "confirmation": confirmation }),
                ))
                .await
                .unwrap(),
        )
        .await
    }

    /// Redeem `code` carrying an arbitrary confirmation object.
    async fn exchange_with(
        state: &AppState,
        code: &str,
        confirmation: Value,
    ) -> (StatusCode, Value) {
        json_response(
            crate::router(state.clone())
                .oneshot(json_request(
                    Method::POST,
                    "/v1/pairing/exchange",
                    json!({ "code": code, "confirmation": confirmation }),
                ))
                .await
                .unwrap(),
        )
        .await
    }

    /// Redeem `code` with the operator's correct password — the default happy path for the tests
    /// that are about something other than the confirmation itself.
    async fn exchange(state: &AppState, code: &str) -> (StatusCode, Value) {
        exchange_with(state, code, json!({ "password": OPERATOR_PASSWORD })).await
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

    // =============================================================================================
    // t70 — the mint must be re-authenticated
    //
    // `ConfirmationAction::DevicePairing` has been floored at `ConfirmWithReauth` since t56-e0 with
    // nothing enforcing it. "Did not mint" is the assertion, not "returned an error": a refused
    // mint must leave no redeemable code behind.
    // =============================================================================================

    #[tokio::test]
    async fn minting_without_a_step_up_proof_mints_no_code() {
        let state = AppState::default();
        let operator = operator_session(&state).await;

        // The body every pre-t70 client sent.
        let (status, body) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    "/v1/pairing/codes",
                    &operator,
                    json!({ "label": "Telemóvel da Amélia" }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        // NOT `body["code"]` — an `ApiError` body carries its own `code` field (the error id), so
        // that assertion would read the refusal's own name and call it a pairing code. The real
        // question is whether a redeemable code exists, which is the registry.
        assert_eq!(
            state.pairing.0.codes.read().await.len(),
            0,
            "no code was minted"
        );
    }

    #[tokio::test]
    async fn minting_with_a_wrong_password_mints_no_code() {
        let state = AppState::default();
        let operator = operator_session(&state).await;

        let (status, body) = mint_with(
            &state,
            &operator,
            json!({ "reauth": { "password": "Cavalo-Errado9!" } }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        // NOT `body["code"]` — an `ApiError` body carries its own `code` field (the error id), so
        // that assertion would read the refusal's own name and call it a pairing code. The real
        // question is whether a redeemable code exists, which is the registry.
        assert_eq!(
            state.pairing.0.codes.read().await.len(),
            0,
            "no code was minted"
        );
    }

    #[tokio::test]
    async fn a_code_refused_at_mint_time_cannot_be_exchanged() {
        // The refusal must not merely hide the code from the response — there must be no code. A
        // status assertion alone would pass even if a code had been minted and dropped on the
        // floor, still redeemable by anyone who could guess it.
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let (status, _) = mint_with(&state, &operator, json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        assert_eq!(
            state.pairing.0.codes.read().await.len(),
            0,
            "a refused mint left no outstanding code"
        );
        assert!(devices_of(&state, &operator).await.is_empty());
    }

    #[tokio::test]
    async fn minting_with_the_correct_password_still_works() {
        let state = AppState::default();
        let operator = operator_session(&state).await;

        let (status, minted) = mint_with(
            &state,
            &operator,
            json!({ "reauth": { "password": OPERATOR_PASSWORD } }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "mint: {minted}");
        assert!(!minted["code"].as_str().unwrap().is_empty());
    }

    // =============================================================================================
    // t70 — the exchange must be confirmed
    //
    // Every refusal test asserts that nothing was PAIRED, not merely that the response was an
    // error: no companion token in the body, and no device row in the operator's list. "Renders a
    // refusal" is not the guard; "does not pair" is.
    // =============================================================================================

    #[tokio::test]
    async fn exchange_without_a_confirmation_does_not_pair() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let code = mint_code(&state, &operator).await;

        // A body carrying no confirmation at all — the shape every pre-t70 client sent.
        let (status, body) = json_response(
            crate::router(state.clone())
                .oneshot(json_request(
                    Method::POST,
                    "/v1/pairing/exchange",
                    json!({ "code": code }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        assert!(body["token"].is_null(), "no companion token was issued");
        assert!(
            devices_of(&state, &operator).await.is_empty(),
            "an unconfirmed exchange enrolled no device"
        );
    }

    #[tokio::test]
    async fn exchange_with_a_wrong_password_does_not_pair() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let code = mint_code(&state, &operator).await;

        let (status, body) =
            exchange_with(&state, &code, json!({ "password": "Cavalo-Errado9!" })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        assert!(body["token"].is_null(), "no companion token was issued");
        assert!(
            devices_of(&state, &operator).await.is_empty(),
            "a wrong password enrolled no device"
        );
    }

    #[tokio::test]
    async fn a_wrong_totp_code_does_not_pair() {
        // A stored TOTP secret needs a durable credential store, so this case cannot run
        // on the in-memory state the password cases use.
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.path.clone());
        let (operator, user_id) = operator_account(&state).await;
        enrol_confirmed_totp(&state, &operator, &user_id).await;
        let code = mint_code(&state, &operator).await;

        let (status, body) = exchange_with(&state, &code, json!({ "totp_code": "000000" })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        assert!(
            devices_of(&state, &operator).await.is_empty(),
            "a wrong code enrolled no device"
        );
    }

    #[tokio::test]
    async fn a_totp_code_confirms_the_exchange_without_a_password() {
        // A stored TOTP secret needs a durable credential store, so this case cannot run
        // on the in-memory state the password cases use.
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.path.clone());
        let (operator, user_id) = operator_account(&state).await;
        let secret = enrol_confirmed_totp(&state, &operator, &user_id).await;
        let code = mint_code(&state, &operator).await;

        // No password anywhere in this body — the point of the password-free path.
        let (status, exchanged) =
            exchange_with(&state, &code, json!({ "totp_code": live_totp_code(&secret) })).await;
        assert_eq!(status, StatusCode::OK, "exchange: {exchanged}");
        assert_eq!(exchanged["confirmed_by"], "totp_code");
        assert_eq!(
            session_user(&state, exchanged["token"].as_str().unwrap()).await["username"],
            "amelia.marques"
        );
        let devices = devices_of(&state, &operator).await;
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0]["confirmed_by"], "totp_code");
    }

    #[tokio::test]
    async fn a_deployment_can_accept_only_password_free_confirmation() {
        // A stored TOTP secret needs a durable credential store, so this case cannot run
        // on the in-memory state the password cases use.
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.path.clone());
        let (operator, user_id) = operator_account(&state).await;
        let secret = enrol_confirmed_totp(&state, &operator, &user_id).await;
        accept_only(&state, &[PairingConfirmationMethod::TotpCode]).await;

        // The operator's own, correct password is now not an accepted proof.
        let refused_code = mint_code(&state, &operator).await;
        let (status, body) = exchange(&state, &refused_code).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "password refused: {body}");
        assert!(
            devices_of(&state, &operator).await.is_empty(),
            "a correct-but-unaccepted password enrolled no device"
        );

        // The accepted method still works.
        let code = mint_code(&state, &operator).await;
        let (status, exchanged) =
            exchange_with(&state, &code, json!({ "totp_code": live_totp_code(&secret) })).await;
        assert_eq!(status, StatusCode::OK, "totp accepted: {exchanged}");
        assert_eq!(exchanged["confirmed_by"], "totp_code");
    }

    #[tokio::test]
    async fn a_deployment_accepting_nothing_pairs_nothing() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        // `AuthSettings::validate` refuses this at the settings door; the gate refuses it here too,
        // so the unsatisfiable configuration is closed at both ends rather than defaulting open.
        accept_only(&state, &[]).await;
        let code = mint_code(&state, &operator).await;

        let (status, body) = exchange(&state, &code).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        assert!(
            devices_of(&state, &operator).await.is_empty(),
            "an empty accepted set enrolled no device"
        );
    }

    #[tokio::test]
    async fn a_totp_code_cannot_confirm_two_pairings() {
        // A stored TOTP secret needs a durable credential store, so this case cannot run
        // on the in-memory state the password cases use.
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.path.clone());
        let (operator, user_id) = operator_account(&state).await;
        let secret = enrol_confirmed_totp(&state, &operator, &user_id).await;
        let presented = live_totp_code(&secret);

        let first = mint_code(&state, &operator).await;
        let (status, exchanged) =
            exchange_with(&state, &first, json!({ "totp_code": presented })).await;
        assert_eq!(status, StatusCode::OK, "first exchange: {exchanged}");

        // The replay guard in `totp::verify_totp_for_user` has spent this step. Same code, fresh
        // pairing code: refused, and the second device is not enrolled.
        let second = mint_code(&state, &operator).await;
        let (status, body) = exchange_with(&state, &second, json!({ "totp_code": presented })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "replay refused: {body}");
        assert_eq!(
            devices_of(&state, &operator).await.len(),
            1,
            "the replayed code enrolled no second device"
        );
    }

    #[tokio::test]
    async fn a_pending_second_factor_cannot_confirm_a_pairing() {
        // A stored TOTP secret needs a durable credential store, so this case cannot run
        // on the in-memory state the password cases use.
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.path.clone());
        let (operator, user_id) = operator_account(&state).await;
        // Enrol but never confirm: a secret exists, an active factor does not.
        let (status, started) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    &format!("/v1/users/{user_id}/two-factor/totp/enrol"),
                    &operator,
                    Value::Null,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "enrol totp: {started}");
        let secret = started["secret"].as_str().unwrap().to_owned();
        accept_only(&state, &[PairingConfirmationMethod::TotpCode]).await;

        let code = mint_code(&state, &operator).await;
        let (status, body) =
            exchange_with(&state, &code, json!({ "totp_code": live_totp_code(&secret) })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        assert!(
            devices_of(&state, &operator).await.is_empty(),
            "an unconfirmed enrolment enrolled no device"
        );
    }

    #[tokio::test]
    async fn a_failed_confirmation_burns_the_pairing_code() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let code = mint_code(&state, &operator).await;

        let (status, _) = exchange_with(&state, &code, json!({ "password": "Cavalo-Errado9!" })).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Retrying the same code with the CORRECT password is refused as an unknown code: one
        // attempt per code, so a live code is not an unlimited guessing target.
        let (status, body) = exchange(&state, &code).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "code is spent: {body}");
        assert!(devices_of(&state, &operator).await.is_empty());
    }

    /// Issue a pairing confirmation code directly, as a successful mint-with-mail would, and return
    /// the plaintext. Bypasses SMTP: these tests are about the gate, and no relay is configured.
    async fn issue_emailed_code(state: &AppState, user_id: Uuid) -> String {
        use crate::auth_token::{AuthTokenPurpose, AuthTokenSubject};
        let purpose = AuthTokenPurpose::DevicePairingConfirmation;
        let (secret, _) = state.auth_tokens.write().await.issue_transcribable(
            purpose,
            AuthTokenSubject::user(user_id),
            purpose.default_ttl(),
            OffsetDateTime::now_utc(),
        );
        secret.expose().to_owned()
    }

    async fn operator_uuid(state: &AppState) -> Uuid {
        let users = state.users.read().await;
        users.values().find(|u| u.active).unwrap().id.0
    }

    #[tokio::test]
    async fn an_emailed_code_confirms_the_exchange_without_a_password() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let user_id = operator_uuid(&state).await;
        let emailed = issue_emailed_code(&state, user_id).await;
        let code = mint_code(&state, &operator).await;

        let (status, exchanged) =
            exchange_with(&state, &code, json!({ "emailed_code": emailed })).await;
        assert_eq!(status, StatusCode::OK, "exchange: {exchanged}");
        assert_eq!(exchanged["confirmed_by"], "emailed_code");
        assert_eq!(devices_of(&state, &operator).await.len(), 1);
    }

    #[tokio::test]
    async fn an_emailed_code_is_accepted_lower_case_and_without_separators() {
        // What a person types back is not byte-identical to what they read. Case and the group
        // hyphens are the two things they reliably vary, and only those two.
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let user_id = operator_uuid(&state).await;
        let emailed = issue_emailed_code(&state, user_id).await;
        let typed = emailed.replace('-', "").to_lowercase();
        assert_ne!(typed, emailed, "the transcription really does differ");
        let code = mint_code(&state, &operator).await;

        let (status, exchanged) =
            exchange_with(&state, &code, json!({ "emailed_code": typed })).await;
        assert_eq!(status, StatusCode::OK, "exchange: {exchanged}");
        assert_eq!(exchanged["confirmed_by"], "emailed_code");
    }

    #[tokio::test]
    async fn an_emailed_code_cannot_confirm_two_pairings() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let user_id = operator_uuid(&state).await;
        let emailed = issue_emailed_code(&state, user_id).await;

        let first = mint_code(&state, &operator).await;
        let (status, _) = exchange_with(&state, &first, json!({ "emailed_code": emailed })).await;
        assert_eq!(status, StatusCode::OK);

        let second = mint_code(&state, &operator).await;
        let (status, body) =
            exchange_with(&state, &second, json!({ "emailed_code": emailed })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "single use: {body}");
        assert_eq!(devices_of(&state, &operator).await.len(), 1);
    }

    #[tokio::test]
    async fn another_users_emailed_code_does_not_confirm_this_pairing() {
        // The purpose matches and the token is live; only the subject differs. Trusting the record
        // because it redeemed would let anyone holding *any* valid pairing code confirm as someone
        // else, so the subject is checked rather than assumed.
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let stranger = issue_emailed_code(&state, Uuid::new_v4()).await;
        let code = mint_code(&state, &operator).await;

        let (status, body) = exchange_with(&state, &code, json!({ "emailed_code": stranger })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        assert!(devices_of(&state, &operator).await.is_empty());
    }

    #[tokio::test]
    async fn a_wrong_emailed_code_does_not_pair() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let user_id = operator_uuid(&state).await;
        issue_emailed_code(&state, user_id).await;
        let code = mint_code(&state, &operator).await;

        let (status, body) =
            exchange_with(&state, &code, json!({ "emailed_code": "AAAA-BBBB-CCCC-DDDD" })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        assert!(devices_of(&state, &operator).await.is_empty());
    }

    #[tokio::test]
    async fn a_deployment_that_does_not_accept_emailed_codes_refuses_one() {
        let state = AppState::default();
        let operator = operator_session(&state).await;
        let user_id = operator_uuid(&state).await;
        let emailed = issue_emailed_code(&state, user_id).await;
        accept_only(&state, &[PairingConfirmationMethod::TotpCode]).await;
        let code = mint_code(&state, &operator).await;

        let (status, body) =
            exchange_with(&state, &code, json!({ "emailed_code": emailed })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "refused: {body}");
        assert!(devices_of(&state, &operator).await.is_empty());
    }

    /// Strip the operator's credentials, leaving a valid session — the t69 legacy state in which
    /// `require_step_up` passes on the session alone. Gives them an address so the refusal under
    /// test is the credential one and not the missing-address one.
    async fn make_credential_less(state: &AppState) {
        let mut users = state.users.write().await;
        let user = users.values_mut().find(|u| u.active).expect("the operator");
        user.password_hash = None;
        user.recovery_hash = None;
        user.email = Some("amelia.marques@exemplo.pt".to_owned());
    }

    #[tokio::test]
    async fn a_credential_less_operator_can_still_mint_on_their_session_alone() {
        // The inherited t69 behaviour, pinned so the next change to it is deliberate. This is NOT
        // a hole on its own — the exchange still has to be confirmed, and this operator holds no
        // password. It is the premise of the test below.
        let state = AppState::default();
        let operator = operator_session(&state).await;
        make_credential_less(&state).await;

        let (status, minted) = mint_with(&state, &operator, json!({})).await;
        assert_eq!(status, StatusCode::OK, "step-up is vacuous: {minted}");
    }

    #[tokio::test]
    async fn a_credential_less_operator_cannot_have_a_code_mailed_to_them() {
        // The chain this refuses: mint on the session alone, then confirm from the mailbox the
        // same unattended browser may already be signed into — a full pairing with no secret the
        // operator knows, turning transient screen access into a durable companion session.
        let state = AppState::default();
        let operator = operator_session(&state).await;
        make_credential_less(&state).await;

        let (status, body) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    "/v1/pairing/codes",
                    &operator,
                    json!({ "email_confirmation_code": true }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "refused: {body}");
        assert_eq!(
            state.pairing.0.codes.read().await.len(),
            0,
            "and no pairing code was left outstanding"
        );
        assert_eq!(
            state.auth_tokens.read().await.len(),
            0,
            "and no confirmation code was ever issued"
        );
    }

    #[tokio::test]
    async fn an_operator_with_a_credential_can_have_a_code_mailed_to_them() {
        // The refusal above must be about the missing credential, not about mail being broken:
        // this operator has a password, so the request gets past the credential gate and fails
        // only at the relay, which no test here configures.
        let state = AppState::default();
        let operator = operator_session(&state).await;
        {
            let mut users = state.users.write().await;
            let user = users.values_mut().find(|u| u.active).expect("the operator");
            user.email = Some("amelia.marques@exemplo.pt".to_owned());
        }

        let (status, body) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    "/v1/pairing/codes",
                    &operator,
                    json!({
                        "confirmation": { "reauth": { "password": OPERATOR_PASSWORD } },
                        "email_confirmation_code": true,
                    }),
                ))
                .await
                .unwrap(),
        )
        .await;
        // Both refusals are 422 and asserting on the prose would be asserting on copy, so the
        // signal is behaviour: the credential gate refuses BEFORE a token is issued, while a
        // relay failure happens after. One issued token therefore means the gate was passed and
        // the request died at the relay — which is the only thing this test claims.
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "no relay here: {body}");
        assert_eq!(
            state.auth_tokens.read().await.len(),
            1,
            "a credentialed operator reached token issuance"
        );
    }

    #[tokio::test]
    async fn asking_to_mail_a_code_with_no_address_refuses_and_mints_nothing() {
        // The operator these tests create has no email address. Refusing loudly beats minting a
        // pairing code whose promised confirmation could never arrive.
        let state = AppState::default();
        let operator = operator_session(&state).await;

        let (status, body) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    "/v1/pairing/codes",
                    &operator,
                    json!({
                        "confirmation": { "reauth": { "password": OPERATOR_PASSWORD } },
                        "email_confirmation_code": true,
                    }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "refused: {body}");
        assert_eq!(
            state.pairing.0.codes.read().await.len(),
            0,
            "no pairing code was left outstanding"
        );
    }

    #[tokio::test]
    async fn a_device_row_written_before_the_confirmation_still_rehydrates() {
        // `DurablePairingDevice` is `deny_unknown_fields` and `from_store` SKIPS a row it cannot
        // parse, so a `confirmed_by` without `#[serde(default)]` would not fail loudly — it would
        // quietly drop every device enrolled before t70 out of the operator's list, taking the
        // ability to revoke them with it. This pins the compatibility, not the field.
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.path.clone());
        let operator = operator_session(&state).await;
        let user_id = {
            let users = state.users.read().await;
            users.values().find(|u| u.active).unwrap().id.0
        };

        let device_id = Uuid::new_v4().to_string();
        let legacy = json!({
            "device_id": device_id,
            "user_id": user_id,
            "label": "Telemóvel antigo",
            "token_sha256": session_token_digest("legacy-companion-token"),
            "created_at_unix": OffsetDateTime::now_utc().unix_timestamp(),
            "revoked_at_unix": null,
        })
        .to_string();
        let store = state.store.clone().expect("a data dir gives a store");
        let id = device_id.clone();
        store
            .persist_blocking_async(move |tx| tx.upsert_pairing_device(&id, &legacy))
            .await
            .expect("write the legacy row");

        let restarted = AppState::with_data_dir(temp.path.clone());
        let devices = devices_of(&restarted, &operator).await;
        assert_eq!(devices.len(), 1, "the pre-t70 row survived rehydration");
        assert_eq!(devices[0]["device_id"], device_id);
        // Not recorded, and rendered as such — never as a method nobody proved.
        assert!(devices[0]["confirmed_by"].is_null());
    }

    #[tokio::test]
    async fn a_device_row_written_by_a_newer_binary_still_rehydrates() {
        // The ROLLBACK direction, and the reason `deny_unknown_fields` is gone. `serde(default)`
        // only protects a new binary reading old rows; nothing protected an old binary reading new
        // ones. With the attribute in place this row would fail to parse and be dropped by
        // `from_store`'s skip — silently emptying the operator's device list and taking their
        // ability to revoke the device with it, on any rollback after a future field is added.
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.path.clone());
        let operator = operator_session(&state).await;
        let user_id = {
            let users = state.users.read().await;
            users.values().find(|u| u.active).unwrap().id.0
        };

        let device_id = Uuid::new_v4().to_string();
        let from_the_future = json!({
            "device_id": device_id,
            "user_id": user_id,
            "label": "Telemóvel do futuro",
            "token_sha256": session_token_digest("future-companion-token"),
            "created_at_unix": OffsetDateTime::now_utc().unix_timestamp(),
            "revoked_at_unix": null,
            "confirmed_by": "password",
            // A field this binary has never heard of, exactly as a newer one would write.
            "kind": "signing_companion",
        })
        .to_string();
        let store = state.store.clone().expect("a data dir gives a store");
        let id = device_id.clone();
        store
            .persist_blocking_async(move |tx| tx.upsert_pairing_device(&id, &from_the_future))
            .await
            .expect("write the newer row");

        let restarted = AppState::with_data_dir(temp.path.clone());
        let devices = devices_of(&restarted, &operator).await;
        assert_eq!(devices.len(), 1, "a newer row survived the rollback");
        assert_eq!(devices[0]["device_id"], device_id);
        assert_eq!(devices[0]["confirmed_by"], "password");
    }

    #[tokio::test]
    async fn the_mint_advertises_the_accepted_methods() {
        let state = AppState::default();
        let operator = operator_session(&state).await;

        let (status, minted) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    "/v1/pairing/codes",
                    &operator,
                    json!({ "confirmation": { "reauth": { "password": OPERATOR_PASSWORD } } }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "mint: {minted}");
        assert_eq!(
            minted["accepted_confirmation_methods"],
            json!(["password", "totp_code", "emailed_code"]),
            "an unconfigured instance accepts every implemented method"
        );

        accept_only(&state, &[PairingConfirmationMethod::TotpCode]).await;
        let (status, minted) = json_response(
            crate::router(state.clone())
                .oneshot(auth_request(
                    Method::POST,
                    "/v1/pairing/codes",
                    &operator,
                    json!({ "confirmation": { "reauth": { "password": OPERATOR_PASSWORD } } }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "mint: {minted}");
        assert_eq!(
            minted["accepted_confirmation_methods"],
            json!(["totp_code"])
        );
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
