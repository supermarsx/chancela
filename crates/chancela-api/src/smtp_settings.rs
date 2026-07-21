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
use crate::smtp::{SmtpClient, SmtpEncryption, SmtpFailure, SmtpMessage, SmtpTrace};
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

/// Send the welcome message for a newly created account (t70, for t71's `send_welcome_email` flag).
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
pub(crate) async fn send_welcome_email(
    state: &AppState,
    recipient_email: &str,
    recipient_name: Option<&str>,
    created_by: Option<&str>,
    // t71: render in the recipient's chosen locale. `None` ⇒ the platform default
    // (`settings.documents.locale`), which is also what an `"auto"` preference resolves to —
    // there is no browser to detect from when the server renders a message.
    locale_override: Option<&str>,
) -> Result<(), ApiError> {
    let Relay {
        client,
        from_address,
        from_name,
    } = build_relay(state, "sending a welcome message").await?;

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
            // The instance's own base URL is not recorded in settings, and guessing one would put a
            // wrong link in front of a new user. Omitted until there is a configured value to use.
            None,
        )
    };

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

    client.send(&message).await.map_err(|failure| {
        // The relay's own code and text, not a generic "could not send" — the same fidelity the
        // test-send gives, because this is the same class of problem.
        ApiError::Unprocessable(format!(
            "the welcome message was not accepted by the relay at stage {}: {}",
            failure.stage.as_str(),
            failure.summary()
        ))
    })?;
    Ok(())
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
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let mut ledger = state.ledger.write().await;
    ledger.append(&actor_label, AUDIT_SCOPE, kind, None, &bytes);
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderCredentialStore;
    use crate::actor::SESSION_TTL_SECS;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chancela_authz::{OWNER_ROLE_ID, READER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId};
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
