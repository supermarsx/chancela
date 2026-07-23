//! Admin-facing outbound-email configuration (t23).
//!
//! The non-secret half of the configuration — host, port, encryption mode, username, sender identity
//! — lives in the settings document as [`EmailSettings`](crate::settings::EmailSettings) and rides
//! the ordinary `GET`/`PUT /v1/settings` round-trip like every other section. This module owns the
//! three things that cannot: the **password**, the **status**, and the **test send**.
//!
//! ## Security posture
//!
//! - **The password is write-only.** It is stored AEAD-encrypted in the same credential store as the
//!   signing-provider secrets ([`CredentialMode::Smtp`]), never in `settings.json`, and no response
//!   type here has a field that could carry it — [`EmailStatusView`] exposes a `password_configured`
//!   boolean and nothing else. It is decrypted at exactly one point: immediately before `AUTH` on a
//!   live connection, into a [`Zeroizing`] buffer.
//! - **Fail closed.** With no key source or no data directory, storing the password is refused with
//!   an actionable error rather than falling back to plaintext.
//! - **Sanitized audit.** Every change appends a ledger event recording *that* the mail password
//!   changed, who changed it, and when — never the value, and never a prefix, suffix or length of it.
//! - **Admin-reserved.** Every handler here requires `settings.manage` at `Scope::Global`, the same
//!   gate as `PUT /v1/settings` and the provider-credential mutations. That permission is held by
//!   Owner and Platform Administrator and deliberately *not* by Tenant Administrator.
//!
//! ## Why the test send returns 200 with a failure body
//!
//! A rejected `AUTH` is not a malformed request — the operator's call was well-formed and the
//! *relay* said no. Modelling it as an HTTP error would flatten `535 5.7.8 authentication failed`
//! into "422". Instead this mirrors the connector-probe pattern already in the codebase: a `200`
//! carrying a structured [`EmailTestResult`] with the stage, the kind, the real SMTP code, the
//! enhanced status code and the server's own text. HTTP errors are reserved for the things that
//! really are request errors: no permission, mail not configured, a bad recipient address.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;
use zeroize::Zeroizing;

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::email_template::{self, TestEmail, WelcomeEmail};
use crate::error::ApiError;
use crate::provider_credentials_write::map_store_err_for;
use crate::secretstore_persist::{FIELD_SMTP_PASSWORD, SmtpCredentialFields};
use crate::settings::EmailSettings;
use crate::smtp::{SmtpClient, SmtpDelivery, SmtpEncryption, SmtpFailure, SmtpMessage, SmtpTrace};
use crate::{AppState, CredentialMode};

/// The ledger scope every mail-configuration change is recorded under.
const AUDIT_SCOPE: &str = "email";

/// The credential store is single-instance for SMTP: one relay account per deployment.
const SMTP_PROVIDER_ID: &str = "";

/// What [`map_store_err_for`] names in its refusals on this surface.
const STORE_SUBJECT: &str = "the SMTP relay password";

/// Longest password we will accept. Generous enough for any app-password or token, bounded so a
/// hostile body cannot be used to grow the sidecar without limit.
const MAX_PASSWORD_LEN: usize = 1024;

// --- DTOs ---------------------------------------------------------------------------------------

/// `PUT /v1/settings/email/password` body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPasswordRequest {
    /// The relay password. Deserialized straight into a zeroizing buffer.
    password: String,
}

// `Debug` is implemented by hand (rather than derived) so the plaintext can never reach a log line
// or a panic message through the request struct.
impl std::fmt::Debug for SetPasswordRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetPasswordRequest { password: *** }")
    }
}

/// `POST /v1/settings/email/test` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestSendRequest {
    /// Where to send the test message.
    to: String,
}

/// `GET /v1/settings/email/status` response. Metadata only — by construction there is no field here
/// that could carry the password.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct EmailStatusView {
    /// Whether a relay password is stored. Never the value, never a hint, never its length.
    pub password_configured: bool,
    /// Whether the configuration is complete enough to attempt a send.
    pub deliverable: bool,
    /// Whether the session will run inside TLS with the current encryption mode.
    pub encrypted: bool,
    /// Non-blocking advisories for the operator (e.g. encryption explicitly disabled).
    pub warnings: Vec<String>,
}

/// `POST /v1/settings/email/test` response.
///
/// The `trace` is the substantial half. An operator diagnosing a relay usually does not have a
/// shell on the box this runs on — self-hosted deployments are exactly the case where "check the
/// server logs" is not an available instruction — so the response has to carry the whole
/// conversation, not a verdict. See [`SmtpTrace`] for what is in it and, importantly, for the two
/// mechanisms that keep the relay password out of it.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct EmailTestResult {
    /// Whether the relay accepted the message.
    pub ok: bool,
    /// Whether the session actually ran inside TLS.
    pub tls: bool,
    /// Whether the session authenticated.
    pub authenticated: bool,
    /// The relay's accepting reply on success (often its queue id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_detail: Option<String>,
    /// The structured failure on rejection: stage, kind, real SMTP code, enhanced code, server text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<SmtpFailure>,
    /// The full protocol trace — stage timeline with per-stage timings and verbatim server replies,
    /// the resolved address, the negotiated TLS version and peer certificate, and the redacted
    /// conversation transcript. Present on success as well as failure: a send that works but runs
    /// unencrypted, or takes 19 seconds, is worth seeing.
    pub trace: SmtpTrace,
}

/// Wire view of one recorded delivery attempt (t108) — the admin surface's row.
///
/// This is a **delivery record, not a queue**: there is no `queued`/`sending` status because
/// nothing drains a queue in this build, and the UI must not imply one exists. Every attempt is
/// terminal — `sent` or `failed`. The full `recipient` and the relay's own `failure_detail` are
/// here on purpose: an operator manages mail from this list, and both live in a table that can be
/// erased on request, which the ledger cannot.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct EmailDeliveryView {
    pub id: String,
    pub template_id: String,
    pub user_id: Option<String>,
    pub recipient: String,
    /// `sent` or `failed`. Never `queued` — see the type note.
    pub status: String,
    pub attempt: i64,
    /// The attempt this one retried, if any, so the admin UI can show the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<i64>,
    /// The relay's own words on a failure. Present only on `failed` rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_detail: Option<String>,
    pub created_at: String,
    /// The ledger event this attempt appended, for cross-reference with the immutable record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_seq: Option<i64>,
    pub actor: String,
    /// Whether this message can be **re-sent** from durable state. A token-bearing message is not
    /// (its secret is unrecoverable); its honest counterpart is **re-issue**, a different operation
    /// under a different permission. See [`delivery_is_resendable`].
    pub resendable: bool,
}

impl From<&chancela_store::StoredEmailDelivery> for EmailDeliveryView {
    fn from(row: &chancela_store::StoredEmailDelivery) -> Self {
        use time::format_description::well_known::Rfc3339;
        EmailDeliveryView {
            id: row.id.clone(),
            template_id: row.template_id.clone(),
            user_id: row.user_id.clone(),
            recipient: row.recipient.clone(),
            status: row.status.clone(),
            attempt: row.attempt,
            previous_id: row.previous_id.clone(),
            failure_stage: row.failure_stage.clone(),
            failure_kind: row.failure_kind.clone(),
            failure_code: row.failure_code,
            failure_detail: row.failure_detail.clone(),
            created_at: row.created_at.format(&Rfc3339).unwrap_or_default(),
            event_seq: row.event_seq,
            actor: row.actor.clone(),
            resendable: delivery_is_resendable(row),
        }
    }
}

// --- Handlers -----------------------------------------------------------------------------------

/// `GET /v1/settings/email/status` — is mail configured, and can it be used?
pub async fn get_email_status(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<EmailStatusView>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;
    let settings = state.settings.read().await.email.clone();
    let password_configured = read_password_configured(&state).await?;
    Ok(Json(status_view(&settings, password_configured)))
}

/// `PUT /v1/settings/email/password` — set or replace the relay password.
pub async fn put_email_password(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Json<EmailStatusView>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;

    let request: SetPasswordRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid request body: {e}")))?;
    let password = Zeroizing::new(request.password);
    if password.is_empty() {
        return Err(ApiError::Unprocessable(
            "password must not be empty; use DELETE to remove the stored password".to_owned(),
        ));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(ApiError::Unprocessable(format!(
            "password must be at most {MAX_PASSWORD_LEN} bytes"
        )));
    }
    // SMTP AUTH carries the password base64-encoded on a single command line, so an embedded CR/LF
    // would let it forge a command. Refuse rather than silently stripping.
    if password.contains(['\r', '\n']) {
        return Err(ApiError::Unprocessable(
            "password must not contain line breaks".to_owned(),
        ));
    }

    let fields = SmtpCredentialFields {
        password: Some(password),
    };
    write_smtp_fields(&state, fields, &[]).await?;

    // Audit records THAT it changed, never what to.
    audit(&state, &actor, &attestor, "email.password.updated").await?;

    let status = status_view(&state.settings.read().await.email.clone(), true);
    Ok(Json(status))
}

/// `DELETE /v1/settings/email/password` — remove the stored relay password.
pub async fn delete_email_password(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<EmailStatusView>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;

    write_smtp_fields(
        &state,
        SmtpCredentialFields::default(),
        &[FIELD_SMTP_PASSWORD],
    )
    .await?;
    audit(&state, &actor, &attestor, "email.password.cleared").await?;

    let status = status_view(&state.settings.read().await.email.clone(), false);
    Ok(Json(status))
}

/// `POST /v1/settings/email/test` — open a real SMTP session and deliver a test message.
///
/// This is the only way an operator can tell configured-and-working from configured-and-silently-
/// broken, so it runs the genuine protocol against the real relay and reports the real answer.
pub async fn post_email_test(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Json<EmailTestResult>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;

    let request: TestSendRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid request body: {e}")))?;
    // Validating (and normalizing) the recipient here means a typo is a clean 422 rather than a
    // confusing relay rejection at RCPT TO.
    let recipient = crate::email::normalize_optional_email(Some(request.to), "to")?
        .ok_or_else(|| ApiError::Unprocessable("to is required".to_owned()))?;

    let Relay {
        client,
        from_address,
        from_name,
    } = build_relay(&state, "sending a test").await?;
    let now = OffsetDateTime::now_utc();
    let sent_at = now.format(&Rfc2822).unwrap_or_default();
    let (instance_name, locale) = {
        let all = state.settings.read().await;
        (
            all.organization
                .name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .unwrap_or(email_template::PRODUCT_NAME)
                .to_owned(),
            all.documents.locale.as_str(),
        )
    };
    let rendered = email_template::test_email(&TestEmail {
        instance_name: &instance_name,
        host: &client.host,
        port: client.port,
        encryption: client.encryption.as_str(),
        authenticated: client.username.is_some(),
        from_address: &from_address,
        to_address: &recipient,
        sent_at: &sent_at,
        locale,
    });
    let message = SmtpMessage {
        from_address: from_address.clone(),
        from_name,
        to_address: recipient.clone(),
        subject: rendered.subject,
        body: rendered.text_body,
        html_body: Some(rendered.html_body),
        date: sent_at.clone(),
        message_id: format!("{}@chancela.invalid", uuid::Uuid::new_v4()),
    };

    let (outcome, trace) = client.send_traced(&message).await;
    let result = match outcome {
        Ok(delivery) => EmailTestResult {
            ok: true,
            tls: delivery.tls,
            authenticated: delivery.authenticated,
            accepted_detail: Some(delivery.accepted_detail),
            failure: None,
            trace,
        },
        Err(failure) => EmailTestResult {
            ok: false,
            // Whether the session was inside TLS when it failed, as observed — a rejection at
            // RCPT TO on an encrypted session is not the same fact as the same rejection in the
            // clear, and only the failure itself knows which happened.
            tls: failure.tls,
            // A failure can only be reported as authenticated if it got past AUTH, which by
            // construction it did not — every post-AUTH stage failure still means no message moved.
            authenticated: false,
            accepted_detail: None,
            failure: Some(failure),
            trace,
        },
    };

    // A test send is an outbound action taken by an administrator; record that it happened and how
    // it ended. The recipient is operator-supplied and non-secret; the password is not involved.
    audit_test(&state, &actor, &attestor, &recipient, &result).await?;

    Ok(Json(result))
}

/// How many recorded deliveries the admin list returns at most. Bounded because the delivery
/// history grows without limit; the list is "most recent first", which is what an operator chasing
/// a just-failed message wants.
const DELIVERIES_PAGE_LIMIT: i64 = 200;

/// `GET /v1/settings/email/deliveries` — the recorded outcome of every outbound message, newest
/// first (t108).
///
/// This is the surface the user asked to "see" and "manage". It is a **delivery record**, not a
/// queue: every row is a terminal `sent`/`failed` outcome, and there is deliberately no pending
/// state to display. Gated on `settings.read` — the same audience as the rest of the email
/// configuration.
pub async fn list_email_deliveries(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<EmailDeliveryView>>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;
    let Some(store) = &state.store else {
        // An in-memory instance keeps no delivery history; an empty list is the honest answer, not
        // an error.
        return Ok(Json(Vec::new()));
    };
    let rows = store
        .read_blocking_async(move |s| s.email_deliveries(DELIVERIES_PAGE_LIMIT))
        .await
        .map_err(|e| ApiError::Internal(format!("reading the delivery record failed: {e}")))?;
    Ok(Json(rows.iter().map(EmailDeliveryView::from).collect()))
}

/// `POST /v1/settings/email/deliveries/{id}/resend` — re-send a recorded message from durable state
/// (t108).
///
/// ## Why this is a *resend* and not a general retry button
///
/// It re-sends only messages whose content is fully derivable from durable non-secret state — today
/// exactly the welcome mail (see [`delivery_is_resendable`]). A token-bearing message
/// (invitation, recovery, 2FA) is refused with `422` and a pointer to re-issue, because its secret
/// is unrecoverable and, more importantly, minting a fresh one **grants access** and so belongs to
/// the token flow's own permission (`user.invite`), never this one. Offering it here would be a
/// privilege-escalation path disguised as a convenience: whoever administers the SMTP relay could
/// mint invitations.
///
/// A resend **inserts a new row** linked to the one it retried by `previous_id`, so the history of
/// attempts is preserved rather than overwritten, and appends its own ledger event (attempt N).
/// Gated on `settings.manage`, the same bar as the test send.
pub async fn resend_email_delivery(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<EmailDeliveryView>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;

    let Some(store) = &state.store else {
        return Err(ApiError::Unprocessable(
            "this instance keeps no delivery record to resend from".to_owned(),
        ));
    };
    let lookup_id = id.clone();
    let previous = store
        .read_blocking_async(move |s| s.email_delivery(&lookup_id))
        .await
        .map_err(|e| ApiError::Internal(format!("reading the delivery record failed: {e}")))?
        .ok_or(ApiError::NotFound)?;

    if !delivery_is_resendable(&previous) {
        // The honest refusal names the alternative rather than silently doing nothing. A
        // token-bearing message is re-issued through its own flow, under its own authority.
        return Err(ApiError::Unprocessable(
            "this message carried a one-time credential and cannot be resent from the delivery \
             record; re-issue it through the flow that owns it (for an invitation, issue a new \
             invite)"
                .to_owned(),
        ));
    }

    // Re-render the welcome message from durable, non-secret account state. The recipient recorded
    // on the row is authoritative; the display name and locale come from the account, so a resend
    // reflects the account as it stands now (e.g. a since-corrected name).
    let user_id = previous
        .user_id
        .as_deref()
        .and_then(|raw| uuid::Uuid::parse_str(raw).ok())
        .ok_or_else(|| {
            ApiError::Unprocessable(
                "this delivery is not linked to an account and cannot be re-rendered".to_owned(),
            )
        })?;
    let (display_name, locale_override) = {
        let users = state.users.read().await;
        let user = users
            .get(&crate::users::UserId(user_id))
            .ok_or(ApiError::NotFound)?;
        (
            user.display_name.clone(),
            user.language.fixed().map(|l| l.as_str().to_owned()),
        )
    };

    let actor_label = actor.resolve("system");
    let outcome = send_welcome_email(
        &state,
        &previous.recipient,
        Some(&display_name),
        // Not the resending operator: they did not create the account, and the welcome body's
        // "created by" line would misstate history if it named them.
        None,
        locale_override.as_deref(),
    )
    .await;

    let new_row = record_send_outcome(
        &state,
        &actor_label,
        &attestor,
        SendRecord {
            template_id: WELCOME_TEMPLATE_ID,
            user_id: Some(user_id),
            recipient: &previous.recipient,
            token_subject: None,
            token_purpose: None,
        },
        &outcome,
        Some(&previous),
    )
    .await?;

    // The resend's own outcome is the response. Unlike account creation, a resend is an operator
    // action *about delivery*, so a relay refusal here is reported to the caller — surfaced as the
    // new `failed` row — rather than swallowed.
    Ok(Json(EmailDeliveryView::from(&new_row)))
}

// --- Sending -------------------------------------------------------------------------------------

/// A relay ready to send, assembled from the settings document plus the stored password.
struct Relay {
    client: SmtpClient,
    from_address: String,
    from_name: Option<String>,
}

/// Build the configured relay, or explain what is missing.
///
/// Shared by the test-send and by [`send_welcome_email`] so there is exactly one place that decides
/// what "mail is configured" means and exactly one place the password is decrypted. `purpose` is
/// spliced into the refusals ("… before sending a test") so the message names the caller's action.
async fn build_relay(state: &AppState, purpose: &str) -> Result<Relay, ApiError> {
    let settings = state.settings.read().await.email.clone();
    let host = settings
        .host
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            ApiError::Unprocessable(format!(
                "email.host is not configured; save the SMTP settings before {purpose}"
            ))
        })?
        .to_owned();
    let from_address = settings
        .from_address
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            ApiError::Unprocessable(format!(
                "email.from_address is not configured; save the SMTP settings before {purpose}"
            ))
        })?
        .to_owned();

    let username = settings
        .username
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_owned);
    // The one place the password is decrypted, and only when a username makes it relevant.
    let password = match &username {
        Some(_) => read_password(state).await?,
        None => None,
    };
    if username.is_some() && password.is_none() {
        return Err(ApiError::Unprocessable(format!(
            "email.username is set but no relay password is stored; save the password before \
             {purpose}"
        )));
    }

    Ok(Relay {
        client: SmtpClient {
            host,
            port: settings.port,
            encryption: settings.encryption,
            username,
            password,
            helo_name: settings.resolved_helo_name(),
        },
        from_address,
        from_name: settings.from_name.clone(),
    })
}

/// Why an outbound send did not deliver, in a shape a recorder can file rather than a string.
///
/// The two arms are genuinely different facts and an operator needs to tell them apart: nobody ever
/// spoke to a relay in the first case, and a relay was reached and refused in the second. Flattening
/// both into one `ApiError` string — which is what this module did before t108 — destroyed the
/// stage, kind and code before anything could record them.
#[derive(Debug)]
pub(crate) enum SendFailure {
    /// Mail is not configured well enough to attempt a send; [`build_relay`] refused. Carries our
    /// own refusal text, which is server-authored and names a missing setting, never a credential.
    NotConfigured(ApiError),
    /// A relay was reached and said no, in its own words.
    Refused(SmtpFailure),
}

impl SendFailure {
    /// The stage this failed at, using the SMTP stage vocabulary plus `not_configured` for the
    /// case that never reached a socket. Enum-valued and therefore safe to store verbatim in a
    /// hash-chained field: unlike a relay's free text, it cannot carry a recipient address.
    fn stage(&self) -> &'static str {
        match self {
            SendFailure::NotConfigured(_) => "not_configured",
            SendFailure::Refused(failure) => failure.stage.as_str(),
        }
    }

    /// The failure kind, same vocabulary rule as [`stage`](Self::stage).
    fn kind(&self) -> &'static str {
        match self {
            SendFailure::NotConfigured(_) => "not_configured",
            SendFailure::Refused(failure) => failure.kind.as_str(),
        }
    }
}

impl From<SendFailure> for ApiError {
    fn from(failure: SendFailure) -> ApiError {
        match failure {
            SendFailure::NotConfigured(error) => error,
            SendFailure::Refused(failure) => ApiError::Unprocessable(format!(
                "the welcome message was not accepted by the relay at stage {}: {}",
                failure.stage.as_str(),
                failure.summary()
            )),
        }
    }
}

/// Send the welcome message for a newly created account (t70, for t71's `send_welcome_email` flag).
///
/// **Private since t108.** [`send_and_record_welcome_email`] is the only crate-visible way to send
/// one, so a new caller cannot accidentally send mail that nothing records — which is exactly how
/// the outcome of the only real message this product sends came to be recorded nowhere at all.
///
/// ## What it does not send
///
/// No password, no token, no sign-in link. [`WelcomeEmail`] has no field that could carry one, so
/// that is a property of the type rather than a rule someone has to remember here — see
/// [`crate::email_template::welcome_email`] for why mail is the wrong channel for a credential.
/// This signature deliberately takes no secret material either.
///
/// ## Why it returns the error instead of raising it
///
/// A welcome mail is a courtesy attached to a user creation, not part of it. The account is already
/// written by the time this runs, so a relay refusal must not fail the create and must not roll
/// anything back — the caller logs it and carries on. Returning `Result` rather than swallowing the
/// error keeps the caller free to surface "the account was created but the mail did not go out",
/// which is the honest thing to tell an administrator.
///
/// ## Which language it renders in (t71)
///
/// `locale_override` first, then `settings.documents.locale`. The override is **the recipient's**
/// stored preference and deliberately never the creating administrator's: an admin working in en-GB
/// must not send a Portuguese colleague an English welcome. Mail is the one surface where "the
/// language of whoever is at the keyboard" is straightforwardly wrong, because nobody is at the
/// keyboard when it is read.
///
/// A user whose preference is `auto` resolves to `None` **at the call site**, so this function never
/// learns that the preference type has an `Auto` case — it only ever sees "a locale, or use the
/// default". That is the right split: "auto" means *detect from the browser*, and there is no
/// browser here, so the platform default is the only honest answer and the caller is the one that
/// knows it.
///
/// An unrecognised tag is not an error: [`crate::email_template::copy_for`] falls back to the source
/// locale, so a stale stored preference sends Portuguese mail rather than no mail.
async fn send_welcome_email(
    state: &AppState,
    recipient_email: &str,
    recipient_name: Option<&str>,
    created_by: Option<&str>,
    // t71: render in the recipient's chosen locale. `None` ⇒ the platform default
    // (`settings.documents.locale`), which is also what an `"auto"` preference resolves to —
    // there is no browser to detect from when the server renders a message.
    locale_override: Option<&str>,
) -> Result<SmtpDelivery, SendFailure> {
    let Relay {
        client,
        from_address,
        from_name,
    } = build_relay(state, "sending a welcome message")
        .await
        .map_err(SendFailure::NotConfigured)?;

    let (instance_name, locale, sign_in_url) = {
        let all = state.settings.read().await;
        (
            all.organization
                .name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .unwrap_or(email_template::PRODUCT_NAME)
                .to_owned(),
            locale_override.unwrap_or_else(|| all.documents.locale.as_str()),
            // t95 P0-3. There is now a configured value to use — and it is the ONLY thing that may
            // be used. `platform.public_base_url` is set by an operator; it is never derived from
            // the `Host` header of whatever request happens to be creating this user, because that
            // is host-header injection and would let a caller aim the link at a domain they own.
            // The original refusal to guess stands unchanged for the unconfigured case: absent
            // means the mail goes out with no sign-in link, not with a plausible-looking one.
            all.platform.resolved_public_base_url(),
        )
    };
    let sign_in_url = sign_in_url.as_deref();

    let rendered = email_template::welcome_email(&WelcomeEmail {
        recipient_name,
        recipient_email,
        created_by,
        instance_name: &instance_name,
        sign_in_url,
        locale,
    });

    let now = OffsetDateTime::now_utc();
    let message = SmtpMessage {
        from_address,
        from_name,
        to_address: recipient_email.to_owned(),
        subject: rendered.subject,
        body: rendered.text_body,
        html_body: Some(rendered.html_body),
        date: now.format(&Rfc2822).unwrap_or_default(),
        message_id: format!("{}@chancela.invalid", uuid::Uuid::new_v4()),
    };

    // The relay's own structured refusal, kept structured. The `ApiError` prose the caller used to
    // get is still available via `From<SendFailure>`, but it is now derived at the point of display
    // rather than at the point of failure — so the recorder above sees stage, kind and code.
    client.send(&message).await.map_err(SendFailure::Refused)
}

// --- Recording outbound sends (t108) --------------------------------------------------------------

/// The ledger scope outbound-message outcomes are recorded under. `"user"` rather than `"email"`:
/// the question these events answer is "what happened to *this person's* invitation", which belongs
/// beside `user.created` in the user's own audit trail, not in the relay's configuration history.
const SEND_SCOPE: &str = "user";

/// A welcome message to send and file the outcome of.
///
/// Grouped into a struct rather than added to an already-five-argument positional list, because the
/// recording wrapper is the entry point new senders will copy and a call site of eight positional
/// arguments is one a future caller gets wrong silently.
pub(crate) struct WelcomeMessage<'a> {
    /// The account the message is about. This is the **pseudonymous key** the outcome is filed
    /// under, and deliberately the only account identifier that reaches the hash chain.
    pub user_id: uuid::Uuid,
    /// Where it is going. Used to send, and to derive the domain that is recorded; the address
    /// itself is not written to the ledger — see [`send_and_record_welcome_email`].
    pub recipient_email: &'a str,
    pub recipient_name: Option<&'a str>,
    /// Who created the account, as the message body names them.
    pub created_by: Option<&'a str>,
    /// The recipient's locale preference; `None` ⇒ the platform default (t71).
    pub locale_override: Option<&'a str>,
}

/// Send a welcome message **and record what happened to it** (t108).
///
/// ## Why this exists
///
/// Before t108 the outcome of the only real mail this product sends was recorded nowhere durable:
/// `create_user` called the sender inline and dropped the `Result` into a `tracing::warn!`. An
/// operator asking "did this person ever receive their invitation?" had no way to answer it from
/// the product. Every send now appends `user.welcome_email_sent` or `user.welcome_email_failed`.
///
/// [`send_welcome_email`] is private so that this is the only way to send one. A recorder a caller
/// can forget to call is a recorder that will eventually not be called.
///
/// ## What reaches the hash chain, and what deliberately does not
///
/// The ledger keeps only a **digest** of the payload (`Ledger::append` hashes it and drops the
/// bytes; the `events` table has no payload column). So the readable facts are the ones in `kind`
/// and `justification`, and both are held to non-personal, enum-or-uuid content:
///
/// - **No body content**, in any form. This function never touches `rendered.text_body` or
///   `html_body` — they exist only inside the private sender and go to the socket. The same line
///   `SmtpTrace` already holds by summarising a body as `<message body: N bytes>`.
/// - **No credential.** Nothing here reads the relay password; it is decrypted only inside
///   `build_relay`, into a `Zeroizing` buffer, and the trace's `&'static str` redaction path keeps
///   it out of diagnostics. This function is downstream of all of that and takes no secret.
/// - **Not the recipient address**, only its **domain**. The address is personal data and a hash
///   chain cannot honour an erasure request. It would also be inert if included: the payload bytes
///   are discarded, so the address would survive only as *preimage to a published digest* — and an
///   e-mail address is low-entropy enough that such a digest is a confirmation oracle, which is a
///   disclosure with no compensating benefit. The domain is what actually diagnoses a relay problem
///   ("everything to one provider is being refused") and is not personal to an individual.
/// - **Not the relay's own refusal text**, for the same reason and one more: an `RCPT TO` rejection
///   routinely quotes the address back (`550 5.1.1 <…>: Recipient address rejected`), so storing it
///   verbatim would reintroduce exactly what the line above excludes. Only the **stage** and
///   **kind** are recorded — enum values that cannot carry an address. The relay's full text still
///   reaches the operator through the caller's log line, at full fidelity and undiminished.
///
/// ## What it returns
///
/// The `Result`, unchanged in meaning: a failed welcome message must not fail the account creation,
/// and the caller stays free to decide that. What changed is that ignoring it no longer makes the
/// failure invisible.
pub(crate) async fn send_and_record_welcome_email(
    state: &AppState,
    actor: &str,
    attestor: &CurrentAttestor,
    message: WelcomeMessage<'_>,
) -> Result<(), ApiError> {
    let outcome = send_welcome_email(
        state,
        message.recipient_email,
        message.recipient_name,
        message.created_by,
        message.locale_override,
    )
    .await;

    // The welcome message carries no bearer credential (no token, no sign-in link — it is the one
    // mail whose content is fully derivable from durable non-secret state), so `token_*` are `None`
    // and this message is resendable. A token-bearing sender would fill them in and be re-issuable
    // rather than resendable.
    record_send_outcome(
        state,
        actor,
        attestor,
        SendRecord {
            template_id: WELCOME_TEMPLATE_ID,
            user_id: Some(message.user_id),
            recipient: message.recipient_email,
            token_subject: None,
            token_purpose: None,
        },
        &outcome,
        None,
    )
    .await?;

    outcome.map(|_| ()).map_err(ApiError::from)
}

/// What a send was, independent of its outcome — the descriptor every sender hands the recorder.
///
/// Deliberately small and non-secret: a template id, the account it concerns, where it went, and a
/// *reference* to any bearer credential (subject + purpose), never the credential itself. There is
/// no field for a rendered body, so the recorder cannot file one even by mistake.
pub(crate) struct SendRecord<'a> {
    pub template_id: &'a str,
    pub user_id: Option<uuid::Uuid>,
    pub recipient: &'a str,
    /// The bearer credential's subject, when the message carried one. Presence of a token is what
    /// makes a message re-issuable rather than resendable.
    pub token_subject: Option<&'a str>,
    pub token_purpose: Option<&'a str>,
}

/// Append the ledger event **and** write the durable delivery row for one send outcome (t108).
///
/// The two records answer different questions and this product wants both:
///
/// - **the ledger event** is immutable and attestable — "an invitation to this account failed, by
///   this operator, at this instant"; it carries only the recipient's *domain* and the failure
///   *stage/kind*, because a hash chain cannot be erased and the relay's own text quotes the
///   address back;
/// - **the `email_deliveries` row** is mutable and operable — it holds the full recipient and the
///   relay's own words so an operator can act on them, and can be erased on request.
///
/// The row references the event by `seq`, so the erasable record and the immutable one can be
/// reconciled. Neither record can hold a rendered body or a token: the ledger drops its payload
/// bytes, and the row has no column for either.
///
/// A store failure here does not un-send a message that already went, and — via the caller's
/// swallow — does not fail an account creation. It fails *this recording*, which the caller logs.
async fn record_send_outcome(
    state: &AppState,
    actor: &str,
    attestor: &CurrentAttestor,
    record: SendRecord<'_>,
    outcome: &Result<SmtpDelivery, SendFailure>,
    // The attempt this one retries, when it is a resend. `None` for a first attempt. Its `id`
    // becomes `previous_id` and its `attempt` is incremented, so history chains rather than
    // overwrites.
    previous: Option<&chancela_store::StoredEmailDelivery>,
) -> Result<chancela_store::StoredEmailDelivery, ApiError> {
    let attempt = previous.map_or(1, |p| p.attempt + 1);
    let user_label = record
        .user_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "-".to_owned());
    // A resend's ledger event names itself as attempt N, so the immutable record distinguishes it
    // from the original send without needing the mutable row.
    let attempt_note = if attempt > 1 {
        format!(" (attempt {attempt})")
    } else {
        String::new()
    };
    let (kind, status, justification, payload) = match outcome {
        Ok(delivery) => (
            "user.welcome_email_sent",
            "sent",
            format!(
                "{} for user {user_label} accepted by the relay{attempt_note}",
                record.template_id
            ),
            serde_json::json!({
                "template": record.template_id,
                "user_id": record.user_id,
                "recipient_domain": recipient_domain(record.recipient),
                "ok": true,
                "tls": delivery.tls,
                "authenticated": delivery.authenticated,
            }),
        ),
        Err(failure) => (
            "user.welcome_email_failed",
            "failed",
            format!(
                "{} for user {user_label} not sent: {} at {}",
                record.template_id,
                failure.kind(),
                failure.stage()
            ),
            serde_json::json!({
                "template": record.template_id,
                "user_id": record.user_id,
                "recipient_domain": recipient_domain(record.recipient),
                "ok": false,
                "failure_stage": failure.stage(),
                "failure_kind": failure.kind(),
                "failure_code": match failure {
                    SendFailure::Refused(f) => f.code,
                    SendFailure::NotConfigured(_) => None,
                },
            }),
        ),
    };
    let event_seq = append_audit_as(
        state,
        actor,
        attestor,
        SEND_SCOPE,
        kind,
        Some(&justification),
        payload,
    )
    .await?;

    // The durable, erasable half. `failure_detail` is the relay's own words — kept only here.
    let (tls, authenticated, failure_stage, failure_kind, failure_code, failure_detail) =
        match outcome {
            Ok(delivery) => (
                Some(delivery.tls),
                Some(delivery.authenticated),
                None,
                None,
                None,
                None,
            ),
            Err(failure) => (
                None,
                None,
                Some(failure.stage().to_owned()),
                Some(failure.kind().to_owned()),
                match failure {
                    SendFailure::Refused(f) => f.code.map(i64::from),
                    SendFailure::NotConfigured(_) => None,
                },
                Some(match failure {
                    SendFailure::Refused(f) => f.summary(),
                    // Our own server-authored refusal, which names a missing setting and carries
                    // no credential. `build_relay` only ever raises `Unprocessable` here.
                    SendFailure::NotConfigured(ApiError::Unprocessable(msg)) => msg.clone(),
                    SendFailure::NotConfigured(_) => "mail is not configured".to_owned(),
                }),
            ),
        };
    let delivery = chancela_store::StoredEmailDelivery {
        id: uuid::Uuid::new_v4().to_string(),
        template_id: record.template_id.to_owned(),
        user_id: record.user_id.map(|id| id.to_string()),
        recipient: record.recipient.to_owned(),
        status: status.to_owned(),
        attempt,
        previous_id: previous.map(|p| p.id.clone()),
        token_subject: record.token_subject.map(str::to_owned),
        token_purpose: record.token_purpose.map(str::to_owned),
        tls,
        authenticated,
        failure_stage,
        failure_kind,
        failure_code,
        failure_detail,
        created_at: OffsetDateTime::now_utc(),
        event_seq: Some(event_seq as i64),
        actor: actor.to_owned(),
    };
    if let Some(store) = &state.store {
        let row = delivery.clone();
        store
            .read_blocking_async(move |s| s.insert_email_delivery(&row))
            .await
            .map_err(|e| ApiError::Internal(format!("recording the send outcome failed: {e}")))?;
    }
    Ok(delivery)
}

/// The template identifier recorded against a welcome message, so a later sender's outcomes are
/// distinguishable from these without adding an event kind per template.
const WELCOME_TEMPLATE_ID: &str = "user.welcome";

/// Whether a recorded delivery can be **re-sent** — as opposed to re-issued.
///
/// True only when the message's content is fully derivable from durable non-secret state, which is
/// the case exactly when it carried no bearer credential. A row with a `token_subject` referenced a
/// token whose secret the server no longer holds (`AuthTokenStore` keeps only `sha256(secret)`), so
/// its original body is *mathematically* unreproducible — not merely disallowed. Such a message is
/// re-issuable instead, which mints a fresh secret and therefore **grants access**; that is a
/// different operation gated on the token flow's own permission (`user.invite`), never on the
/// email-settings permission. See [`resend_email_delivery`].
///
/// Today the only re-renderable template is the welcome message: given a `user_id`, its body is
/// rebuilt from the account's stored display name and locale, with no secret anywhere in the path.
fn delivery_is_resendable(row: &chancela_store::StoredEmailDelivery) -> bool {
    row.token_subject.is_none() && row.template_id == WELCOME_TEMPLATE_ID
}

/// The domain half of an address, lowercased, or `"unknown"` when there is no `@` to split on.
///
/// Only ever the part after the last `@`: a local part can itself contain one in a quoted address,
/// and taking the first would leak a fragment of the personal half into the record.
fn recipient_domain(address: &str) -> String {
    match address.rsplit_once('@') {
        Some((_, domain)) if !domain.is_empty() => domain.to_ascii_lowercase(),
        _ => "unknown".to_owned(),
    }
}

// --- Helpers ------------------------------------------------------------------------------------

fn status_view(settings: &EmailSettings, password_configured: bool) -> EmailStatusView {
    let host_set = settings
        .host
        .as_deref()
        .map(str::trim)
        .is_some_and(|h| !h.is_empty());
    let from_set = settings
        .from_address
        .as_deref()
        .map(str::trim)
        .is_some_and(|a| !a.is_empty());
    let username_set = settings
        .username
        .as_deref()
        .map(str::trim)
        .is_some_and(|u| !u.is_empty());

    let mut warnings = Vec::new();
    if settings.encryption == SmtpEncryption::None {
        warnings.push(
            "Encryption is disabled: the relay password and every message body cross the network \
             in the clear."
                .to_owned(),
        );
    }
    if username_set && !password_configured {
        warnings.push(
            "A username is configured but no password is stored, so authentication will fail."
                .to_owned(),
        );
    }
    if password_configured && !username_set {
        warnings.push(
            "A password is stored but no username is configured, so it will never be used."
                .to_owned(),
        );
    }

    EmailStatusView {
        deliverable: settings.enabled
            && host_set
            && from_set
            && (!username_set || password_configured),
        encrypted: settings.encryption.is_encrypted(),
        password_configured,
        warnings,
    }
}

/// Whether a password is stored, without decrypting anything.
async fn read_password_configured(state: &AppState) -> Result<bool, ApiError> {
    let credentials = state.provider_credentials.clone();
    let entries = tokio::task::spawn_blocking(move || {
        credentials.entry_metadata(CredentialMode::Smtp, SMTP_PROVIDER_ID)
    })
    .await
    .map_err(|e| std::panic::resume_unwind(e.into_panic()))
    .and_then(|r| r)
    .map_err(|e| map_store_err_for(STORE_SUBJECT, e))?;
    Ok(entries.iter().any(|entry| {
        entry
            .fields
            .iter()
            .any(|(name, _)| name == FIELD_SMTP_PASSWORD)
    }))
}

/// Decrypt the stored password, or `None` when there is none.
async fn read_password(state: &AppState) -> Result<Option<Zeroizing<String>>, ApiError> {
    let credentials = state.provider_credentials.clone();
    let record = tokio::task::spawn_blocking(move || {
        credentials.read_runtime(CredentialMode::Smtp, SMTP_PROVIDER_ID)
    })
    .await
    .map_err(|e| std::panic::resume_unwind(e.into_panic()))
    .and_then(|r| r)
    .map_err(|e| map_store_err_for(STORE_SUBJECT, e))?;
    Ok(record.and_then(|record| {
        record
            .fields
            .get(FIELD_SMTP_PASSWORD)
            .map(|value| Zeroizing::new(value.to_string()))
    }))
}

/// Write/clear the SMTP credential fields. Offloaded to the blocking pool for the same reason the
/// provider-credential handlers do it: the store's persistence path is synchronous and, under the
/// Postgres backend, would otherwise drive a `block_on` on a runtime worker.
async fn write_smtp_fields(
    state: &AppState,
    fields: SmtpCredentialFields,
    clear: &'static [&'static str],
) -> Result<(), ApiError> {
    use crate::secretstore_persist::CredentialFieldSet as _;

    let set = fields.into_set_pairs();
    let credentials = state.provider_credentials.clone();
    tokio::task::spawn_blocking(move || {
        credentials.put_entry(
            CredentialMode::Smtp,
            SMTP_PROVIDER_ID,
            "default",
            None,
            set,
            clear,
        )
    })
    .await
    .map_err(|e| std::panic::resume_unwind(e.into_panic()))
    .and_then(|r| r)
    .map_err(|e| map_store_err_for(STORE_SUBJECT, e))
}

async fn audit(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    kind: &str,
) -> Result<(), ApiError> {
    append_audit(state, actor, attestor, kind, serde_json::json!({})).await
}

async fn audit_test(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    recipient: &str,
    result: &EmailTestResult,
) -> Result<(), ApiError> {
    let payload = serde_json::json!({
        "recipient": recipient,
        "ok": result.ok,
        "tls": result.tls,
        "authenticated": result.authenticated,
        "failure_stage": result.failure.as_ref().map(|f| f.stage.as_str()),
        "failure_kind": result.failure.as_ref().map(|f| f.kind.as_str()),
        "failure_code": result.failure.as_ref().and_then(|f| f.code),
        // The relay's own words, so the ledger explains a failed test without a second round-trip.
        // Server-supplied and non-secret; the password is never part of a reply.
        "failure_summary": result.failure.as_ref().map(|f| f.summary()),
    });
    append_audit(state, actor, attestor, "email.test_sent", payload).await
}

async fn append_audit(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    kind: &str,
    payload: serde_json::Value,
) -> Result<(), ApiError> {
    let actor_label = actor.resolve("system");
    append_audit_as(
        state,
        &actor_label,
        attestor,
        AUDIT_SCOPE,
        kind,
        None,
        payload,
    )
    .await
    .map(|_seq| ())
}

/// [`append_audit`] for a caller that already holds a resolved actor label and needs to choose the
/// scope and justification — the outbound-send recorder, whose events belong in the `user` scope
/// (t108) and whose justification is the only field an operator can actually read back.
///
/// Returns the appended event's global `seq`, so the delivery row can reference the immutable
/// record it sits beside.
async fn append_audit_as(
    state: &AppState,
    actor_label: &str,
    attestor: &CurrentAttestor,
    scope: &str,
    kind: &str,
    justification: Option<&str>,
    payload: serde_json::Value,
) -> Result<u64, ApiError> {
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let mut ledger = state.ledger.write().await;
    let seq = ledger
        .append(actor_label, scope, kind, justification, &bytes)
        .seq;
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderCredentialStore;
    use crate::actor::SESSION_TTL_SECS;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chancela_authz::{OWNER_ROLE_ID, READER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId};
    use chancela_store::StoredEmailDelivery;
    use serde_json::{Value, json};
    use std::path::{Path as StdPath, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tower::ServiceExt;
    use uuid::Uuid;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    /// A fixed DB key so the derived-root key source resolves deterministically (mirrors the
    /// `secretstore_persist` / `provider_credentials_write` tests).
    const TEST_DB_KEY: &[u8] = b"t23-smtp-settings-test-db-key-000001";

    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let seq = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("chancela-smtp-{}-{seq}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self { dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn state_with_store(dir: &StdPath) -> AppState {
        AppState {
            provider_credentials: Arc::new(ProviderCredentialStore::load_with_db_key(
                dir,
                TEST_DB_KEY,
                false,
            )),
            ..AppState::default()
        }
    }

    async fn seed_token(state: &AppState, role: RoleId) -> String {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: format!("amelia.marques.{}", Uuid::new_v4()),
            display_name: "Amélia Marques".to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(role, Scope::Global)],
            language: Default::default(),
        };
        state.users.write().await.insert(uid, user);
        let token = Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(SESSION_TTL_SECS),
            },
        );
        token
    }

    async fn send_with(
        state: AppState,
        req: Request<Body>,
        token: Option<&str>,
    ) -> (StatusCode, Value) {
        let req = match token {
            Some(t) => {
                let mut r = req;
                r.headers_mut()
                    .insert("x-chancela-session", t.parse().unwrap());
                r
            }
            None => req,
        };
        let response = crate::router(state)
            .oneshot(req)
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("body is JSON")
        };
        (status, value)
    }

    fn body_req(method: &str, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    fn del(uri: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    /// Build a full settings document with the email section filled in and everything else default,
    /// which is what `PUT /v1/settings` expects (the wire shape is whole-document).
    fn settings_body(email: EmailSettings) -> Value {
        let settings = crate::settings::Settings {
            email,
            ..Default::default()
        };
        serde_json::to_value(settings).expect("settings serialize")
    }

    fn relay_settings(port: u16) -> EmailSettings {
        EmailSettings {
            enabled: true,
            host: Some("127.0.0.1".to_owned()),
            port,
            // The fake relay below speaks plain SMTP, so the test opts out of encryption the same
            // way an operator would have to: explicitly.
            encryption: SmtpEncryption::None,
            allow_insecure: true,
            username: Some("sistema".to_owned()),
            from_address: Some("sistema@encosto-estrategico.pt".to_owned()),
            from_name: Some("Encosto Estratégico Lda".to_owned()),
            helo_name: None,
        }
    }

    /// A one-shot fake SMTP server. `auth_reply` is what it answers the `AUTH` command with, which is
    /// how the tests drive a realistic rejection. Returns the bound port.
    async fn fake_relay(auth_reply: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut stream = BufReader::new(socket);
            let mut write = |s: String| s;
            let _ = &mut write;
            stream
                .get_mut()
                .write_all(b"220 relay.example.pt ESMTP ready\r\n")
                .await
                .expect("greeting");
            loop {
                let mut line = String::new();
                if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let upper = line.trim_end().to_ascii_uppercase();
                let reply = if upper.starts_with("EHLO") {
                    "250-relay.example.pt\r\n250-PIPELINING\r\n250 AUTH PLAIN LOGIN\r\n".to_owned()
                } else if upper.starts_with("AUTH") {
                    format!("{auth_reply}\r\n")
                } else if upper.starts_with("QUIT") {
                    let _ = stream.get_mut().write_all(b"221 Bye\r\n").await;
                    return;
                } else {
                    "250 Ok\r\n".to_owned()
                };
                if stream.get_mut().write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
        port
    }

    /// A relay that accepts everything and **hands back the message it received** (t70).
    ///
    /// [`fake_relay`] answers the conversation but discards the body, which is all the test-send
    /// tests need. The welcome-mail tests need the opposite: what actually went over the wire, so
    /// they can assert the MIME structure, the language, and — the point — that no credential is in
    /// it. Asserting on the rendered template alone would prove nothing about what was *sent*.
    async fn capturing_relay() -> (u16, Arc<tokio::sync::Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let captured = Arc::new(tokio::sync::Mutex::new(String::new()));
        let sink = Arc::clone(&captured);
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut stream = BufReader::new(socket);
            stream
                .get_mut()
                .write_all(b"220 relay.example.pt ESMTP ready\r\n")
                .await
                .expect("greeting");
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
                if in_data {
                    if trimmed != "." {
                        sink.lock().await.push_str(&line);
                        continue;
                    }
                    in_data = false;
                    let _ = stream
                        .get_mut()
                        .write_all(b"250 2.0.0 Ok: queued as 8F2A1\r\n")
                        .await;
                    continue;
                }
                let upper = trimmed.to_ascii_uppercase();
                let reply = if upper.starts_with("EHLO") {
                    "250-relay.example.pt\r\n250-PIPELINING\r\n250 AUTH PLAIN LOGIN\r\n".to_owned()
                } else if upper.starts_with("AUTH") {
                    "235 2.7.0 Authentication successful\r\n".to_owned()
                } else if upper.starts_with("DATA") {
                    in_data = true;
                    "354 End data with <CR><LF>.<CR><LF>\r\n".to_owned()
                } else if upper.starts_with("QUIT") {
                    let _ = stream.get_mut().write_all(b"221 Bye\r\n").await;
                    return;
                } else {
                    "250 Ok\r\n".to_owned()
                };
                if stream.get_mut().write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
        (port, captured)
    }

    /// Point `state` at a relay on `port`, in `locale`, with a stored password.
    async fn configure_relay(state: &AppState, port: u16, locale: crate::settings::Locale) {
        {
            let mut settings = state.settings.write().await;
            settings.email = EmailSettings {
                enabled: true,
                host: Some("127.0.0.1".to_owned()),
                port,
                // The loopback fake relay speaks no TLS; the encryption paths are covered against a
                // real handshake in `smtp.rs`.
                encryption: SmtpEncryption::None,
                username: Some("sistema".to_owned()),
                from_address: Some("sistema@encosto-estrategico.pt".to_owned()),
                from_name: Some("Encosto Estratégico Lda".to_owned()),
                helo_name: None,
                allow_insecure: true,
            };
            settings.documents.locale = locale;
            settings.organization.name = Some("Encosto Estratégico Lda".to_owned());
        }
        write_smtp_fields(
            state,
            SmtpCredentialFields {
                password: Some(Zeroizing::new(RELAY_PASSWORD.to_owned())),
            },
            &[],
        )
        .await
        .expect("store the relay password");
    }

    /// The relay password used by the welcome-mail tests, so the leak assertion has one needle.
    const RELAY_PASSWORD: &str = "Palavra-Passe-Do-Relay-9!";

    /// Decode the base64 parts of a captured message back to text, so assertions read against the
    /// prose a recipient sees rather than against an encoding.
    fn decode_parts(raw: &str) -> String {
        use base64::Engine as _;
        let mut out = String::new();
        for block in raw.split("\r\n\r\n").skip(1) {
            let joined: String = block
                .lines()
                .take_while(|l| !l.starts_with("--"))
                .collect::<Vec<_>>()
                .join("");
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(joined.trim())
                && let Ok(text) = String::from_utf8(bytes)
            {
                out.push_str(&text);
                out.push('\n');
            }
        }
        out
    }

    // --- The welcome message, end to end over a real socket (t70) --------------------------------

    /// The seam between t71's `send_welcome_email` flag and this sender: given configured SMTP, a
    /// real multipart message with both parts actually reaches the relay.
    #[tokio::test]
    async fn the_welcome_message_is_delivered_as_multipart_with_both_parts() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let (port, captured) = capturing_relay().await;
        configure_relay(&state, port, crate::settings::Locale::PtPt).await;

        send_welcome_email(
            &state,
            "amelia.marques@encosto-estrategico.pt",
            Some("Amélia Marques"),
            Some("Rui Bastos"),
            None,
        )
        .await
        .expect("the relay accepted the welcome message");

        let raw = captured.lock().await.clone();
        assert!(!raw.is_empty(), "no message reached the relay");
        assert!(
            raw.contains("Content-Type: multipart/alternative;"),
            "the delivered message is not multipart: {raw}"
        );
        // Both parts, and the text one first — a client shows the last part it understands.
        let text_at = raw.find("Content-Type: text/plain").expect("text part");
        let html_at = raw.find("Content-Type: text/html").expect("html part");
        assert!(text_at < html_at, "the HTML part preceded the text part");

        let decoded = decode_parts(&raw);
        assert!(decoded.contains("Amélia Marques"), "{decoded}");
        assert!(decoded.contains("Rui Bastos"), "{decoded}");
        assert!(
            decoded.contains("amelia.marques@encosto-estrategico.pt"),
            "{decoded}"
        );
        // The accented subject survived as RFC 2047 rather than raw UTF-8 in a header.
        assert!(raw.contains("Subject: =?UTF-8?B?"), "{raw}");
    }

    /// t71's `locale_override`: the message renders in the **recipient's** language, not the
    /// instance default. An admin working in one language must not send a colleague a welcome in it.
    #[tokio::test]
    async fn the_welcome_message_renders_in_the_recipients_locale_not_the_instance_default() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let (port, captured) = capturing_relay().await;
        // The instance default is Portuguese...
        configure_relay(&state, port, crate::settings::Locale::PtPt).await;

        // ...but this recipient chose German.
        send_welcome_email(
            &state,
            "amelia.marques@encosto-estrategico.pt",
            Some("Amélia Marques"),
            None,
            Some("de-DE"),
        )
        .await
        .expect("the relay accepted the welcome message");

        let decoded = decode_parts(&captured.lock().await.clone());
        let german = crate::email_template::copy_for("de-DE");
        assert!(
            decoded.contains(german.welcome_never_sends),
            "the message did not render in the recipient's locale: {decoded}"
        );
        assert!(
            !decoded.contains(crate::email_template::copy_for("pt-PT").welcome_never_sends),
            "the instance default locale leaked into the message: {decoded}"
        );
    }

    /// `None` keeps the pre-t71 behaviour exactly: the platform default.
    #[tokio::test]
    async fn no_locale_override_falls_back_to_the_platform_default() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let (port, captured) = capturing_relay().await;
        configure_relay(&state, port, crate::settings::Locale::DeDe).await;

        send_welcome_email(
            &state,
            "amelia.marques@encosto-estrategico.pt",
            None,
            None,
            None,
        )
        .await
        .expect("the relay accepted the welcome message");

        let decoded = decode_parts(&captured.lock().await.clone());
        assert!(
            decoded.contains(crate::email_template::copy_for("de-DE").welcome_never_sends),
            "the platform default locale was not used: {decoded}"
        );
    }

    /// **The cross-seam test.** Everything above drives [`send_welcome_email`] directly, which
    /// proves the *sender* honours `locale_override` — but not that `create_user` actually reads the
    /// new account's preference and passes it. A refactor that dropped `locale_override` on the
    /// floor at the call site, or passed the acting administrator's language instead, would leave
    /// every test above green.
    ///
    /// So this one goes through `POST /v1/users` with t71's `send_welcome_email` flag: the instance
    /// default is Portuguese, the *created user* chose German, and the message that reaches the
    /// relay must be German. Suggested by t71, and they were right that nothing covered it.
    #[tokio::test]
    async fn a_user_created_with_a_language_preference_is_welcomed_in_that_language() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let (port, captured) = capturing_relay().await;
        // The instance speaks Portuguese...
        configure_relay(&state, port, crate::settings::Locale::PtPt).await;

        // ...the new account speaks German, and asks to be told it exists.
        let (status, body) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/users",
                json!({
                    "username": "amelia.marques",
                    "display_name": "Amélia Marques",
                    "email": "amelia.marques@encosto-estrategico.pt",
                    "password": "Teste-Forte7!X",
                    "language": "de-DE",
                    "send_welcome_email": true,
                }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        // The send is fire-and-forget relative to the response, so wait for the body to land rather
        // than racing it.
        let mut raw = String::new();
        for _ in 0..100 {
            raw = captured.lock().await.clone();
            if !raw.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(!raw.is_empty(), "no welcome message reached the relay");

        let decoded = decode_parts(&raw);
        assert!(
            decoded.contains(crate::email_template::copy_for("de-DE").welcome_never_sends),
            "the created user's language did not reach the message: {decoded}"
        );
        assert!(
            !decoded.contains(crate::email_template::copy_for("pt-PT").welcome_never_sends),
            "the instance default was used instead of the recipient's preference: {decoded}"
        );
        // And still no credential, on the path a real account actually takes.
        assert!(
            !decoded.contains("Teste-Forte7!X"),
            "the new account's password was emailed"
        );
        assert!(
            !decoded.contains(RELAY_PASSWORD),
            "the relay password was emailed"
        );
    }

    /// **The load-bearing one.** Whatever the template says, what matters is what crossed the wire:
    /// the delivered message must carry no password, token or link. Asserted against the raw octets
    /// *and* the decoded parts, because a credential hidden in a base64 body would pass a naive
    /// scan of the former.
    #[tokio::test]
    async fn the_delivered_welcome_message_carries_no_credential() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let (port, captured) = capturing_relay().await;
        configure_relay(&state, port, crate::settings::Locale::PtPt).await;

        send_welcome_email(
            &state,
            "amelia.marques@encosto-estrategico.pt",
            Some("Amélia Marques"),
            Some("Rui Bastos"),
            None,
        )
        .await
        .expect("the relay accepted the welcome message");

        let raw = captured.lock().await.clone();
        let decoded = decode_parts(&raw);
        assert!(
            !decoded.is_empty(),
            "nothing decoded, so this proved nothing"
        );

        for haystack in [&raw, &decoded] {
            assert!(
                !haystack.contains(RELAY_PASSWORD),
                "the relay password reached the message body"
            );
            // No link of any kind: no sign-in URL is configured, and a token would need one.
            assert!(!haystack.contains("http://"), "a link reached the message");
            assert!(!haystack.contains("https://"), "a link reached the message");
            assert!(
                !haystack.to_lowercase().contains("token"),
                "the word 'token' reached the message"
            );
        }
        // And it says so, which is what lets a recipient recognise a later message that does as a
        // forgery.
        assert!(
            decoded.contains(crate::email_template::copy_for("pt-PT").welcome_never_sends),
            "{decoded}"
        );
    }

    // --- Recording the outcome of a send (t108) --------------------------------------------------

    /// A relay that gets as far as `RCPT TO` and refuses, **quoting the recipient's address back**
    /// in its reply — which is what real relays do (`550 5.1.1 <…>: Recipient address rejected`).
    ///
    /// That detail is the whole point of this helper rather than a generic rejection: it makes the
    /// leakage assertion below load-bearing. A record that stored "the relay's own failure text"
    /// verbatim would pass a test against a relay that answered `550 no`, and would silently write
    /// a recipient's address into an append-only chain the moment it met a relay that answered like
    /// a real one.
    async fn address_quoting_rejecting_relay() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut stream = BufReader::new(socket);
            stream
                .get_mut()
                .write_all(b"220 relay.example.pt ESMTP ready\r\n")
                .await
                .expect("greeting");
            loop {
                let mut line = String::new();
                if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let upper = line.trim_end_matches(['\r', '\n']).to_ascii_uppercase();
                let reply = if upper.starts_with("EHLO") {
                    "250-relay.example.pt\r\n250-PIPELINING\r\n250 AUTH PLAIN LOGIN\r\n".to_owned()
                } else if upper.starts_with("AUTH") {
                    "235 2.7.0 Authentication successful\r\n".to_owned()
                } else if upper.starts_with("RCPT") {
                    format!("550 5.1.1 <{RECIPIENT}>: Recipient address rejected: no such user\r\n")
                } else if upper.starts_with("QUIT") {
                    let _ = stream.get_mut().write_all(b"221 Bye\r\n").await;
                    return;
                } else {
                    "250 Ok\r\n".to_owned()
                };
                if stream.get_mut().write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
        port
    }

    /// The one address these tests send to, so every leak assertion has a single needle.
    const RECIPIENT: &str = "amelia.marques@encosto-estrategico.pt";

    /// Everything an operator can actually read back off an event. Deliberately *not* the payload:
    /// `Ledger::append` hashes the payload and drops the bytes, and the `events` table has no
    /// column for it, so a test that asserted against the payload would be asserting against data
    /// no operator will ever see — and would report a leak-free record that leaked.
    async fn readable_events(state: &AppState) -> Vec<(String, String, String, String)> {
        state
            .ledger
            .read()
            .await
            .events()
            .iter()
            .map(|e| {
                (
                    e.kind.clone(),
                    e.scope.clone(),
                    e.actor.clone(),
                    e.justification.clone().unwrap_or_default(),
                )
            })
            .collect()
    }

    fn welcome_message(user_id: uuid::Uuid) -> WelcomeMessage<'static> {
        WelcomeMessage {
            user_id,
            recipient_email: RECIPIENT,
            recipient_name: Some("Amélia Marques"),
            created_by: Some("Rui Bastos"),
            locale_override: None,
        }
    }

    /// The gap t108 exists to close: a send that worked is now a fact in the ledger, not a
    /// discarded `Ok`.
    #[tokio::test]
    async fn a_delivered_welcome_message_is_recorded_as_sent() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let (port, _captured) = capturing_relay().await;
        configure_relay(&state, port, crate::settings::Locale::PtPt).await;
        let user_id = uuid::Uuid::new_v4();

        send_and_record_welcome_email(
            &state,
            "rui.bastos",
            &CurrentAttestor::default(),
            welcome_message(user_id),
        )
        .await
        .expect("the relay accepted the welcome message");

        let events = readable_events(&state).await;
        let (kind, scope, actor, justification) = events
            .iter()
            .find(|(kind, ..)| kind.starts_with("user.welcome_email"))
            .expect("the send was recorded");
        assert_eq!(kind, "user.welcome_email_sent");
        assert_eq!(
            scope, "user",
            "the outcome belongs in the user's audit trail"
        );
        assert_eq!(actor, "rui.bastos", "the record names who caused the send");
        assert!(
            justification.contains(&user_id.to_string()),
            "the record does not say which account it is about: {justification}"
        );
    }

    /// **The one that closes the reported gap.** A relay refusal used to vanish into a
    /// `tracing::warn!`, so an operator could not tell "invitation delivered" from "invitation
    /// silently refused" — for the only real message this product sends.
    #[tokio::test]
    async fn a_refused_welcome_message_is_recorded_as_failed_and_still_reports_the_error() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let port = address_quoting_rejecting_relay().await;
        configure_relay(&state, port, crate::settings::Locale::PtPt).await;
        let user_id = uuid::Uuid::new_v4();

        let error = send_and_record_welcome_email(
            &state,
            "rui.bastos",
            &CurrentAttestor::default(),
            welcome_message(user_id),
        )
        .await
        .expect_err("the relay refused the recipient");
        // The caller still gets the relay's own words at full fidelity — that half is unchanged,
        // and is now the *only* place they appear.
        let reported = format!("{error:?}");
        assert!(reported.contains("rcpt_to"), "{reported}");
        assert!(reported.contains("550"), "{reported}");

        let events = readable_events(&state).await;
        let (kind, scope, _, justification) = events
            .iter()
            .find(|(kind, ..)| kind.starts_with("user.welcome_email"))
            .expect("the refusal was recorded");
        assert_eq!(kind, "user.welcome_email_failed");
        assert_eq!(scope, "user");
        // Enough to act on: which account, and where in the conversation it died.
        assert!(
            justification.contains(&user_id.to_string()),
            "{justification}"
        );
        assert!(
            justification.contains("rcpt_to"),
            "the record does not say where it failed: {justification}"
        );
    }

    /// Mail that was never configured is a *different* fact from a relay that said no, and an
    /// operator chasing a missing invitation needs to tell them apart — one is their own settings,
    /// the other is the recipient's provider. Neither reached a socket in the same way.
    #[tokio::test]
    async fn an_unconfigured_relay_is_recorded_as_a_failure_too() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let user_id = uuid::Uuid::new_v4();

        send_and_record_welcome_email(
            &state,
            "rui.bastos",
            &CurrentAttestor::default(),
            welcome_message(user_id),
        )
        .await
        .expect_err("no relay is configured");

        let events = readable_events(&state).await;
        let (kind, _, _, justification) = events
            .iter()
            .find(|(kind, ..)| kind.starts_with("user.welcome_email"))
            .expect("the unattempted send was recorded");
        assert_eq!(kind, "user.welcome_email_failed");
        assert!(
            justification.contains("not_configured"),
            "an unconfigured relay is indistinguishable from a rejection: {justification}"
        );
    }

    /// **The load-bearing one, and the counterpart of
    /// [`the_delivered_welcome_message_carries_no_credential`].** That test guards what leaves the
    /// process; this guards what the process keeps.
    ///
    /// Asserted against every readable field of every event — not against the record this task
    /// wrote, because a leak that mattered would be one some *other* append introduced.
    #[tokio::test]
    async fn no_readable_field_of_the_record_carries_an_address_a_body_or_a_credential() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        // The relay quotes the address back in its refusal, so a record that stored the relay's
        // text verbatim would fail here — which is exactly the regression being guarded.
        let port = address_quoting_rejecting_relay().await;
        configure_relay(&state, port, crate::settings::Locale::PtPt).await;

        send_and_record_welcome_email(
            &state,
            "rui.bastos",
            &CurrentAttestor::default(),
            welcome_message(uuid::Uuid::new_v4()),
        )
        .await
        .expect_err("the relay refused the recipient");

        let events = readable_events(&state).await;
        assert!(
            events
                .iter()
                .any(|(k, ..)| k == "user.welcome_email_failed"),
            "nothing was recorded, so this test proved nothing"
        );
        // The body a recipient would have read, in the locale it was rendered in.
        let body_phrase = crate::email_template::copy_for("pt-PT").welcome_never_sends;
        for (kind, scope, actor, justification) in &events {
            for field in [kind, scope, actor, justification] {
                assert!(
                    !field.contains(RECIPIENT),
                    "a recipient address reached a readable ledger field: {field}"
                );
                assert!(
                    !field.contains("amelia.marques"),
                    "the local part of an address reached a readable ledger field: {field}"
                );
                assert!(
                    !field.contains(RELAY_PASSWORD),
                    "the relay password reached a readable ledger field: {field}"
                );
                assert!(
                    !field.contains(body_phrase),
                    "message body content reached a readable ledger field: {field}"
                );
                assert!(
                    !field.contains("Recipient address rejected"),
                    "the relay's verbatim text reached a readable ledger field, and it quotes \
                     the address: {field}"
                );
            }
        }
    }

    /// The durable half: a store-backed instance writes an `email_deliveries` **row** whose full
    /// recipient and whose relay text are present — the erasable record an operator manages — while
    /// the same attempt's ledger event holds neither. This is the split the whole design turns on,
    /// so it is asserted against both records at once.
    #[tokio::test]
    async fn a_store_backed_send_writes_an_erasable_row_that_the_ledger_event_does_not_mirror() {
        let temp = TempDir::new();
        // A store-backed state, unlike `state_with_store`, actually persists the delivery row.
        let state = crate::AppState::with_data_dir(&temp.dir);
        let port = address_quoting_rejecting_relay().await;
        configure_relay(&state, port, crate::settings::Locale::PtPt).await;
        let user_id = uuid::Uuid::new_v4();

        send_and_record_welcome_email(
            &state,
            "rui.bastos",
            &CurrentAttestor::default(),
            welcome_message(user_id),
        )
        .await
        .expect_err("the relay refused the recipient");

        // The row: the full address and the relay's own words are here, where they can be erased.
        let rows = state
            .store
            .as_ref()
            .expect("store-backed")
            .email_deliveries(10)
            .expect("read deliveries");
        assert_eq!(rows.len(), 1, "exactly one attempt was recorded");
        let row = &rows[0];
        assert_eq!(row.status, "failed");
        assert_eq!(row.recipient, RECIPIENT, "the row keeps the full recipient");
        assert_eq!(row.failure_stage.as_deref(), Some("rcpt_to"));
        assert_eq!(row.template_id, WELCOME_TEMPLATE_ID);
        assert_eq!(row.user_id.as_deref(), Some(user_id.to_string().as_str()));
        assert_eq!(row.attempt, 1);
        assert!(
            row.previous_id.is_none(),
            "a first attempt links to nothing"
        );
        assert!(
            row.token_subject.is_none(),
            "the welcome message carries no bearer credential"
        );
        assert!(
            row.failure_detail
                .as_deref()
                .is_some_and(|d| d.contains(RECIPIENT)),
            "the relay's own words, which quote the address, live in the erasable row"
        );

        // The ledger event for the same attempt mirrors none of that: no full address, no relay
        // text. The row references it by seq, so the two can be reconciled without duplicating the
        // sensitive fields into the immutable record.
        let events = readable_events(&state).await;
        for (_, _, _, justification) in &events {
            assert!(!justification.contains(RECIPIENT), "{justification}");
            assert!(
                !justification.contains("Recipient address rejected"),
                "the relay's verbatim text reached the immutable ledger: {justification}"
            );
        }
        assert!(
            row.event_seq.is_some(),
            "the erasable row must reference the immutable event it sits beside"
        );
    }

    /// A token-bearing message is **not resendable** and a welcome message is, decided purely from
    /// the durable row. This is the guard that keeps a resend button from becoming a
    /// privilege-escalation path: a message that carried a credential can only be re-issued, under
    /// the token flow's authority, never re-sent from here.
    #[test]
    fn resendability_is_decided_by_whether_the_message_carried_a_credential() {
        let base = StoredEmailDelivery {
            id: "x".to_owned(),
            template_id: WELCOME_TEMPLATE_ID.to_owned(),
            user_id: Some(uuid::Uuid::new_v4().to_string()),
            recipient: RECIPIENT.to_owned(),
            status: "failed".to_owned(),
            attempt: 1,
            previous_id: None,
            token_subject: None,
            token_purpose: None,
            tls: None,
            authenticated: None,
            failure_stage: Some("rcpt_to".to_owned()),
            failure_kind: Some("rejected".to_owned()),
            failure_code: Some(550),
            failure_detail: Some("550 no".to_owned()),
            created_at: OffsetDateTime::now_utc(),
            event_seq: Some(1),
            actor: "rui.bastos".to_owned(),
        };
        assert!(delivery_is_resendable(&base), "welcome mail is resendable");

        // A welcome-shaped row that nonetheless references a token is not resendable: the presence
        // of a credential reference is decisive, whatever the template says.
        let with_token = StoredEmailDelivery {
            token_subject: Some("amelia.marques@encosto-estrategico.pt".to_owned()),
            token_purpose: Some("invite".to_owned()),
            ..base.clone()
        };
        assert!(!delivery_is_resendable(&with_token));

        // An invite template is not resendable even with no token subject recorded: we have no
        // renderer that can rebuild it without the secret, so the honest answer is "re-issue".
        let invite = StoredEmailDelivery {
            template_id: "user.invite".to_owned(),
            ..base
        };
        assert!(!delivery_is_resendable(&invite));
    }

    /// Seed a store-backed account with a known id, so a resend can re-render from durable state.
    async fn seed_recipient_account(state: &AppState) -> uuid::Uuid {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;
        let uid = UserId(uuid::Uuid::new_v4());
        let user = User {
            id: uid,
            username: "amelia.marques".to_owned(),
            display_name: "Amélia Marques".to_owned(),
            email: Some(RECIPIENT.to_owned()),
            created_at: OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            active: true,
            password_hash: None,
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: Vec::new(),
            language: crate::users::UserLanguage::Fixed(crate::settings::Locale::PtPt),
        };
        state.users.write().await.insert(uid, user);
        uid.0
    }

    /// End to end through the router: a failed welcome delivery is resent by an administrator, and
    /// the resend **appends** a new attempt linked to the original rather than overwriting it — the
    /// operable half of "manageable". Driven through `POST …/resend` so the permission gate and the
    /// route are exercised, not just the handler body.
    #[tokio::test]
    async fn a_failed_welcome_delivery_can_be_resent_and_the_attempt_chains() {
        let temp = TempDir::new();
        let state = crate::AppState::with_data_dir(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let user_id = seed_recipient_account(&state).await;

        // First attempt: the relay refuses, so a `failed` row lands.
        let reject_port = address_quoting_rejecting_relay().await;
        configure_relay(&state, reject_port, crate::settings::Locale::PtPt).await;
        send_and_record_welcome_email(
            &state,
            "rui.bastos",
            &CurrentAttestor::default(),
            welcome_message(user_id),
        )
        .await
        .expect_err("the relay refused");

        let failed = state.store.as_ref().unwrap().email_deliveries(10).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].status, "failed");
        let failed_id = failed[0].id.clone();

        // Point at a working relay and resend the failed attempt through the real endpoint.
        let (ok_port, _captured) = capturing_relay().await;
        configure_relay(&state, ok_port, crate::settings::Locale::PtPt).await;
        let (status, body) = send_with(
            state.clone(),
            body_req(
                "POST",
                &format!("/v1/settings/email/deliveries/{failed_id}/resend"),
                json!({}),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["status"], "sent",
            "the resend reached the working relay"
        );
        assert_eq!(body["attempt"], 2, "a resend is the next attempt");
        assert_eq!(body["previous_id"], failed_id);
        assert_eq!(body["resendable"], true);

        // The history chains rather than overwrites: both attempts survive.
        let all = state.store.as_ref().unwrap().email_deliveries(10).unwrap();
        assert_eq!(all.len(), 2, "the resend appended; it did not overwrite");
    }

    /// A token-bearing delivery is **refused** at resend with a pointer to re-issue, not silently
    /// resent — the privilege-escalation path the design closes. Also through the router.
    #[tokio::test]
    async fn a_token_bearing_delivery_is_refused_at_resend_and_pointed_to_reissue() {
        let temp = TempDir::new();
        let state = crate::AppState::with_data_dir(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        // Record an invite delivery directly: it references a token subject, so it is not
        // resendable regardless of its template.
        let invite = StoredEmailDelivery {
            id: "inv-1".to_owned(),
            template_id: "user.invite".to_owned(),
            user_id: None,
            recipient: RECIPIENT.to_owned(),
            status: "failed".to_owned(),
            attempt: 1,
            previous_id: None,
            token_subject: Some(RECIPIENT.to_owned()),
            token_purpose: Some("invite".to_owned()),
            tls: None,
            authenticated: None,
            failure_stage: Some("rcpt_to".to_owned()),
            failure_kind: Some("rejected".to_owned()),
            failure_code: Some(550),
            failure_detail: Some("550 no".to_owned()),
            created_at: OffsetDateTime::now_utc(),
            event_seq: Some(1),
            actor: "rui.bastos".to_owned(),
        };
        state
            .store
            .as_ref()
            .unwrap()
            .insert_email_delivery(&invite)
            .unwrap();

        let (status, body) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/settings/email/deliveries/inv-1/resend",
                json!({}),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("re-issue"),
            "the refusal names the alternative: {body}"
        );

        // And nothing was sent or appended — the refusal is before any send.
        assert_eq!(
            state
                .store
                .as_ref()
                .unwrap()
                .email_deliveries(10)
                .unwrap()
                .len(),
            1,
            "a refused resend must not append an attempt"
        );
    }

    /// The list endpoint returns the recorded deliveries newest-first with `resendable` derived,
    /// and is gated on `settings.read`.
    #[tokio::test]
    async fn the_admin_list_returns_recorded_deliveries_with_resendability() {
        let temp = TempDir::new();
        let state = crate::AppState::with_data_dir(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let user_id = seed_recipient_account(&state).await;

        let (port, _captured) = capturing_relay().await;
        configure_relay(&state, port, crate::settings::Locale::PtPt).await;
        send_and_record_welcome_email(
            &state,
            "rui.bastos",
            &CurrentAttestor::default(),
            welcome_message(user_id),
        )
        .await
        .expect("delivered");

        let (status, body) = send_with(
            state.clone(),
            body_req("GET", "/v1/settings/email/deliveries", json!({})),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows = body.as_array().expect("a list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["status"], "sent");
        assert_eq!(rows[0]["recipient"], RECIPIENT);
        assert_eq!(rows[0]["resendable"], true);

        // Reading the record is `settings.read` (the audience is the whole email-config surface),
        // but *resending* is `settings.manage`: an outbound action a plain reader must not take.
        let reader_row_id = rows[0]["id"].as_str().unwrap().to_owned();
        let reader = seed_token(&state, READER_ROLE_ID).await;
        let (status, _) = send_with(
            state.clone(),
            body_req(
                "POST",
                &format!("/v1/settings/email/deliveries/{reader_row_id}/resend"),
                json!({}),
            ),
            Some(&reader),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a reader must not be able to trigger an outbound resend"
        );
    }

    /// The domain is recorded and the local part is not, so a relay-wide problem is diagnosable
    /// without writing an individual's address into a chain that cannot honour an erasure request.
    #[test]
    fn only_the_domain_half_of_an_address_is_derived_for_the_record() {
        assert_eq!(
            recipient_domain("amelia.marques@Encosto-Estrategico.PT"),
            "encosto-estrategico.pt"
        );
        // A quoted local part may itself contain an `@`; splitting on the first would carry a
        // fragment of the personal half into the record.
        assert_eq!(recipient_domain("\"a@b\"@example.pt"), "example.pt");
        assert_eq!(recipient_domain("malformed"), "unknown");
        assert_eq!(recipient_domain("trailing@"), "unknown");
    }

    // --- Settings round-trip, password write-only ------------------------------------------------

    #[tokio::test]
    async fn email_settings_round_trip_and_the_password_is_never_echoed() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        let email = EmailSettings {
            enabled: true,
            host: Some("smtp.encosto-estrategico.pt".to_owned()),
            port: 587,
            encryption: SmtpEncryption::StartTls,
            username: Some("sistema".to_owned()),
            from_address: Some("sistema@encosto-estrategico.pt".to_owned()),
            from_name: Some("Encosto Estratégico Lda".to_owned()),
            helo_name: None,
            allow_insecure: false,
        };
        let (status, _) = send_with(
            state.clone(),
            body_req("PUT", "/v1/settings", settings_body(email)),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Store the password through its own endpoint.
        let (status, body) = send_with(
            state.clone(),
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "correct-horse-battery-staple" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["password_configured"], json!(true));

        // The non-secret settings round-trip intact...
        let (status, got) = send_with(state.clone(), get("/v1/settings"), Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["email"]["host"], json!("smtp.encosto-estrategico.pt"));
        assert_eq!(got["email"]["port"], json!(587));
        assert_eq!(got["email"]["encryption"], json!("starttls"));
        assert_eq!(got["email"]["username"], json!("sistema"));

        // ...and the password appears nowhere in the settings document, under any key.
        let rendered = got.to_string();
        assert!(
            !rendered.contains("correct-horse-battery-staple"),
            "the settings document must never carry the SMTP password"
        );
        assert!(
            got["email"].get("password").is_none(),
            "there must be no password field in the email settings"
        );

        // Nor in the status view.
        let (status, view) = send_with(
            state.clone(),
            get("/v1/settings/email/status"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["password_configured"], json!(true));
        assert_eq!(view["deliverable"], json!(true));
        assert!(!view.to_string().contains("correct-horse-battery-staple"));

        // Clearing it is reflected immediately.
        let (status, view) = send_with(
            state.clone(),
            del("/v1/settings/email/password"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["password_configured"], json!(false));
        assert_eq!(
            view["deliverable"],
            json!(false),
            "a username with no password is not deliverable"
        );
    }

    #[tokio::test]
    async fn changing_the_password_is_audited_without_recording_it() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        let (status, _) = send_with(
            state.clone(),
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "correct-horse-battery-staple" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let ledger = state.ledger.read().await;
        let events = ledger.events();
        let entry = events
            .iter()
            .find(|e| e.kind == "email.password.updated")
            .expect("the password change is recorded in the ledger");
        assert_eq!(entry.scope, "email");
        assert!(
            !entry.actor.is_empty(),
            "the ledger must record who changed it"
        );
        // The whole ledger — payloads included — must not contain the secret.
        let rendered = serde_json::to_string(&events).expect("ledger serializes");
        assert!(
            !rendered.contains("correct-horse-battery-staple"),
            "the audit ledger must record that the password changed, never its value"
        );
    }

    // --- Encryption is on by default and off only on purpose --------------------------------------

    #[tokio::test]
    async fn disabling_encryption_is_refused_without_an_explicit_acknowledgement() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        let email = EmailSettings {
            enabled: true,
            host: Some("smtp.encosto-estrategico.pt".to_owned()),
            encryption: SmtpEncryption::None,
            allow_insecure: false,
            from_address: Some("sistema@encosto-estrategico.pt".to_owned()),
            ..EmailSettings::default()
        };
        let (status, body) = send_with(
            state.clone(),
            body_req("PUT", "/v1/settings", settings_body(email.clone())),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"].as_str().unwrap_or_default().contains("clear"),
            "the refusal must say why: {body}"
        );

        // With the acknowledgement it saves, and the status view warns about it loudly.
        let acknowledged = EmailSettings {
            allow_insecure: true,
            ..email
        };
        let (status, _) = send_with(
            state.clone(),
            body_req("PUT", "/v1/settings", settings_body(acknowledged)),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_, view) = send_with(state, get("/v1/settings/email/status"), Some(&token)).await;
        assert_eq!(view["encrypted"], json!(false));
        assert!(
            view["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .any(|w| w.as_str().unwrap_or_default().contains("in the clear")),
            "a cleartext relay must carry a visible warning: {view}"
        );
    }

    #[tokio::test]
    async fn a_default_deployment_defaults_to_starttls() {
        let email = EmailSettings::default();
        assert_eq!(email.encryption, SmtpEncryption::StartTls);
        assert_eq!(email.port, crate::settings::DEFAULT_SMTP_PORT);
        assert!(!email.allow_insecure);
    }

    // --- The test send reports the relay's real answer --------------------------------------------

    #[tokio::test]
    async fn the_test_send_surfaces_the_relays_real_auth_rejection() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let port = fake_relay("535 5.7.8 Error: authentication failed").await;

        let (status, _) = send_with(
            state.clone(),
            body_req("PUT", "/v1/settings", settings_body(relay_settings(port))),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send_with(
            state.clone(),
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "wrong-password" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/settings/email/test",
                json!({ "to": "amelia.marques@encosto-estrategico.pt" }),
            ),
            Some(&token),
        )
        .await;

        // A relay rejection is not a bad request — the call was fine, the relay said no.
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], json!(false));
        let failure = &body["failure"];
        assert_eq!(failure["stage"], json!("auth"), "{body}");
        assert_eq!(failure["kind"], json!("rejected"), "{body}");
        // The whole point: the operator sees the server's real code and words, not "send failed".
        assert_eq!(failure["code"], json!(535), "{body}");
        assert_eq!(failure["enhanced_code"], json!("5.7.8"), "{body}");
        assert_eq!(
            failure["detail"],
            json!("Error: authentication failed"),
            "{body}"
        );
        assert!(
            !body.to_string().contains("wrong-password"),
            "a failure report must never echo the password"
        );
    }

    #[tokio::test]
    async fn the_test_send_reports_relay_denial_distinctly_from_bad_credentials() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        // The relay accepts AUTH; the generic "250 Ok" branch then answers MAIL FROM, and this
        // rejection arrives at RCPT TO instead — a different stage, which is the distinction an
        // operator needs.
        let port = fake_relay("235 2.7.0 Authentication successful").await;

        send_with(
            state.clone(),
            body_req("PUT", "/v1/settings", settings_body(relay_settings(port))),
            Some(&token),
        )
        .await;
        send_with(
            state.clone(),
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "right-password" }),
            ),
            Some(&token),
        )
        .await;

        let (status, body) = send_with(
            state.clone(),
            body_req(
                "POST",
                "/v1/settings/email/test",
                json!({ "to": "amelia.marques@encosto-estrategico.pt" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // The fake relay answers "250 Ok" to DATA rather than the required 354, so the session fails
        // at DATA — proving the stage tracks where the protocol actually broke.
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["failure"]["stage"], json!("data"), "{body}");
        assert_eq!(body["failure"]["code"], json!(250), "{body}");
        // The relay ran with encryption explicitly off, so the report must say the session was in
        // the clear — even though it got all the way to DATA.
        assert_eq!(body["tls"], json!(false), "{body}");
        assert_eq!(body["failure"]["tls"], json!(false), "{body}");
    }

    #[tokio::test]
    async fn the_test_send_reports_an_unreachable_relay_rather_than_a_generic_error() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        // Bind and immediately drop, so the port is almost certainly closed but well-formed.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        send_with(
            state.clone(),
            body_req("PUT", "/v1/settings", settings_body(relay_settings(port))),
            Some(&token),
        )
        .await;
        send_with(
            state.clone(),
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "irrelevant" }),
            ),
            Some(&token),
        )
        .await;

        let (status, body) = send_with(
            state,
            body_req(
                "POST",
                "/v1/settings/email/test",
                json!({ "to": "amelia.marques@encosto-estrategico.pt" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["failure"]["stage"], json!("connect"), "{body}");
        // The detail names the address that could not be reached.
        assert!(
            body["failure"]["detail"]
                .as_str()
                .unwrap_or_default()
                .contains(&port.to_string()),
            "the failure should name the unreachable address: {body}"
        );
    }

    #[tokio::test]
    async fn a_starttls_relay_that_does_not_offer_starttls_is_refused_rather_than_downgraded() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        // The fake relay's EHLO advertises AUTH but never STARTTLS.
        let port = fake_relay("235 2.7.0 Authentication successful").await;

        let email = EmailSettings {
            encryption: SmtpEncryption::StartTls,
            allow_insecure: false,
            ..relay_settings(port)
        };
        send_with(
            state.clone(),
            body_req("PUT", "/v1/settings", settings_body(email)),
            Some(&token),
        )
        .await;
        send_with(
            state.clone(),
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "some-password" }),
            ),
            Some(&token),
        )
        .await;

        let (status, body) = send_with(
            state,
            body_req(
                "POST",
                "/v1/settings/email/test",
                json!({ "to": "amelia.marques@encosto-estrategico.pt" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["failure"]["stage"], json!("starttls"), "{body}");
        assert_eq!(body["failure"]["kind"], json!("tls_unsupported"), "{body}");
        assert_eq!(
            body["tls"],
            json!(false),
            "the session must not report TLS it never had"
        );
    }

    #[tokio::test]
    async fn a_test_send_is_refused_before_connecting_when_mail_is_not_configured() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        let (status, body) = send_with(
            state,
            body_req(
                "POST",
                "/v1/settings/email/test",
                json!({ "to": "amelia.marques@encosto-estrategico.pt" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("email.host"),
            "{body}"
        );
    }

    // --- Admin-reserved ----------------------------------------------------------------------------

    #[tokio::test]
    async fn non_admin_roles_cannot_read_or_change_the_mail_configuration() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let leitor = seed_token(&state, READER_ROLE_ID).await;

        for req in [
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "nope" }),
            ),
            del("/v1/settings/email/password"),
            body_req(
                "POST",
                "/v1/settings/email/test",
                json!({ "to": "amelia.marques@encosto-estrategico.pt" }),
            ),
        ] {
            let uri = req.uri().to_string();
            let (status, _) = send_with(state.clone(), req, Some(&leitor)).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{uri} must be reserved to administrators"
            );
        }
    }

    #[tokio::test]
    async fn an_unauthenticated_caller_cannot_touch_the_mail_configuration() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        // Seed a user so the server is past first-run (where some endpoints are auth-exempt).
        let _ = seed_token(&state, OWNER_ROLE_ID).await;

        let (status, _) = send_with(
            state.clone(),
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "nope" }),
            ),
            None,
        )
        .await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
            "an anonymous caller must be refused, got {status}"
        );
    }

    // --- Input hygiene -----------------------------------------------------------------------------

    #[tokio::test]
    async fn a_password_containing_a_line_break_is_refused() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        // A CR/LF in an AUTH argument is SMTP command injection.
        let (status, body) = send_with(
            state,
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "secret\r\nQUIT" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }

    #[tokio::test]
    async fn an_empty_password_is_refused_so_clearing_is_always_explicit() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        let (status, body) = send_with(
            state,
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "" }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("DELETE"),
            "the refusal should point at the right verb: {body}"
        );
    }

    #[tokio::test]
    async fn enabling_mail_without_a_host_or_sender_is_refused() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        let (status, _) = send_with(
            state.clone(),
            body_req(
                "PUT",
                "/v1/settings",
                settings_body(EmailSettings {
                    enabled: true,
                    ..EmailSettings::default()
                }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // But a half-filled form can still be saved while it is being set up.
        let (status, _) = send_with(
            state,
            body_req(
                "PUT",
                "/v1/settings",
                settings_body(EmailSettings {
                    enabled: false,
                    host: Some("smtp.encosto-estrategico.pt".to_owned()),
                    ..EmailSettings::default()
                }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_smtp_password_is_not_reachable_through_the_signing_credentials_api() {
        let temp = TempDir::new();
        let state = state_with_store(&temp.dir);
        let token = seed_token(&state, OWNER_ROLE_ID).await;

        send_with(
            state.clone(),
            body_req(
                "PUT",
                "/v1/settings/email/password",
                json!({ "password": "correct-horse-battery-staple" }),
            ),
            Some(&token),
        )
        .await;

        // The mail account shares the credential store, but it is not a signing provider: it must not
        // appear in the Assinaturas list...
        let (status, list) = send_with(
            state.clone(),
            get("/v1/signature/provider-credentials"),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !list.to_string().contains("smtp"),
            "the SMTP record must not surface on the signing-credentials list: {list}"
        );

        // ...nor be writable through its entry API.
        let (status, _) = send_with(
            state,
            body_req(
                "POST",
                "/v1/signature/provider-credentials/smtp/_/entries",
                json!({ "set": { "smtp_password": "x" } }),
            ),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    fn configured() -> EmailSettings {
        EmailSettings {
            enabled: true,
            host: Some("smtp.encosto-estrategico.pt".to_owned()),
            from_address: Some("sistema@encosto-estrategico.pt".to_owned()),
            username: Some("sistema".to_owned()),
            ..EmailSettings::default()
        }
    }

    #[test]
    fn status_is_deliverable_only_when_the_password_backs_the_username() {
        assert!(!status_view(&configured(), false).deliverable);
        assert!(status_view(&configured(), true).deliverable);
    }

    #[test]
    fn status_warns_when_a_username_has_no_password() {
        let status = status_view(&configured(), false);
        assert!(
            status
                .warnings
                .iter()
                .any(|w| w.contains("no password is stored")),
            "expected a missing-password warning, got {:?}",
            status.warnings
        );
    }

    #[test]
    fn status_warns_when_a_password_has_no_username() {
        let settings = EmailSettings {
            username: None,
            ..configured()
        };
        let status = status_view(&settings, true);
        assert!(
            status
                .warnings
                .iter()
                .any(|w| w.contains("no username is configured")),
            "expected an orphan-password warning, got {:?}",
            status.warnings
        );
        // With no username, a stored password is irrelevant and must not block delivery.
        assert!(status.deliverable);
    }

    #[test]
    fn status_warns_loudly_when_encryption_is_disabled() {
        let settings = EmailSettings {
            encryption: SmtpEncryption::None,
            allow_insecure: true,
            ..configured()
        };
        let status = status_view(&settings, true);
        assert!(!status.encrypted);
        assert!(
            status
                .warnings
                .iter()
                .any(|w| w.contains("cross the network in the clear")),
            "expected a cleartext warning, got {:?}",
            status.warnings
        );
    }

    #[test]
    fn status_of_an_unconfigured_deployment_is_not_deliverable_and_is_encrypted_by_default() {
        let status = status_view(&EmailSettings::default(), false);
        assert!(!status.deliverable);
        assert!(!status.password_configured);
        // The default is STARTTLS, so a fresh deployment reports encrypted with no warnings.
        assert!(status.encrypted);
        assert!(status.warnings.is_empty());
    }

    #[test]
    fn status_view_has_no_field_that_could_carry_the_password() {
        // A structural guard: serializing a status can only ever produce these four keys, so a future
        // edit that adds a secret-bearing field to `EmailStatusView` fails here.
        let json = serde_json::to_value(status_view(&configured(), true)).expect("serialize");
        let object = json.as_object().expect("object");
        let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "deliverable",
                "encrypted",
                "password_configured",
                "warnings"
            ]
        );
    }

    #[test]
    fn set_password_request_debug_never_renders_the_secret() {
        let request = SetPasswordRequest {
            password: "correct-horse-battery-staple".to_owned(),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("correct-horse"));
        assert!(rendered.contains("***"));
    }

    /// The test message must identify the session it is proving — this instance, this relay, this
    /// recipient, this time — or it proves nothing an operator can act on. Carried over from the
    /// pre-t70 inline body, now asserted against the themed template.
    #[test]
    fn the_test_message_names_the_session_it_proves_and_never_the_password() {
        let rendered = email_template::test_email(&TestEmail {
            instance_name: "Encosto Estratégico Lda",
            host: "smtp.encosto-estrategico.pt",
            port: 587,
            encryption: SmtpEncryption::StartTls.as_str(),
            authenticated: true,
            from_address: "sistema@encosto-estrategico.pt",
            to_address: "amelia.marques@encosto-estrategico.pt",
            sent_at: "Mon, 20 Jul 2026 09:00:00 +0100",
            locale: "pt-PT",
        });

        for body in [&rendered.text_body, &rendered.html_body] {
            assert!(body.contains("smtp.encosto-estrategico.pt:587"), "{body}");
            assert!(body.contains("starttls"), "{body}");
            assert!(body.contains("Encosto Estratégico Lda"), "{body}");
            assert!(
                body.contains("amelia.marques@encosto-estrategico.pt"),
                "{body}"
            );
            assert!(body.contains("Mon, 20 Jul 2026 09:00:00 +0100"), "{body}");
            // What it does *not* prove, which is the honesty half.
            assert!(
                body.contains("Não prova a entrega na caixa de entrada"),
                "{body}"
            );
        }
        // The relay password is never an input to the template, so there is nothing to leak — but
        // the test-send is exactly where a future edit might casually add it "for debugging".
        assert!(!rendered.text_body.contains("Palavra-Passe"));
        assert!(!rendered.html_body.contains("Palavra-Passe"));
    }
}
