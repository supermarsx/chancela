//! The API's JSON error type.
//!
//! Every failing handler returns an [`ApiError`], which renders as a JSON body with the
//! status code pinned in the contract (plan §2.1). The base shape is `{"error": "...", "code": "..."}`;
//! two variants used by the compliance/seal flow add a structured `issues` or `warnings` array
//! alongside it. Keeping one error type (ARC-02, thin API) means callers get a uniform shape
//! regardless of which layer failed.
//!
//! # Localisation: a stable code on the wire, the copy on the client (t58)
//!
//! `error` is **English operator detail** and stays that way. It is what the server logs, what the
//! `body["error"]` assertions read, and what an operator quotes in a bug report. It is deliberately
//! *not* the user-facing sentence.
//!
//! [`ApiError::code`] adds a stable, machine-readable identifier next to it. The web client owns the
//! pt-PT copy and maps `code` → a localised headline, keeping the English `error` demoted into a
//! technical-details block rather than discarding it. All fourteen locales' i18n machinery is
//! TypeScript, so the server negotiates no locale and ships no translated prose; codes are English
//! identifiers, not copy.
//!
//! Nothing here is subtractive: `error` is never removed, no constructor signature changes, and every
//! existing structured field (`issues`, `warnings`, `failed_rules`, `offset`, `pin_status`,
//! `tries_left`) renders exactly as before.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chancela_cae::CaeError;
use chancela_core::{BookError, NipcError, SealError};
use chancela_registry::RegistryError;
use serde::Serialize;

use crate::dto::IssueView;

/// A request could not be fulfilled. Each variant maps to one HTTP status.
#[derive(Debug)]
pub enum ApiError {
    /// The submitted NIPC failed format or control-digit validation (422).
    InvalidNipc(NipcError),
    /// The addressed resource does not exist (404).
    NotFound,
    /// A sign-in secret / current-secret check failed, or was required and absent (401). Used by
    /// the password-gated session and secret/attestation-key endpoints (plan t29 §4.2/§4.3). The
    /// message never echoes the submitted secret.
    Unauthorized(String),
    /// The session is valid but not authorized to perform this cross-user operation (403). Distinct
    /// from [`Unauthorized`](ApiError::Unauthorized) (401 = no/invalid session or a self-service
    /// wrong-password): a 403 means "you are signed in, but you may not do this to another user
    /// without the required proof" (t51). The message is honest and never echoes any secret. On the
    /// cross-user secret/attestation-key endpoints this is returned uniformly for every no-valid-proof
    /// case (wrong password, no proof, or a target that does not exist) so it never enumerates users.
    Forbidden(String),
    /// Too many failed sign-in attempts for this user; the caller is in backoff (429). Carries a
    /// human, PT message with the seconds remaining (plan t29 §4.5).
    TooManyRequests(String),
    /// A precondition on the resource's state was not met, e.g. drafting into a non-open
    /// book or sealing an act that is not `Signing` (409).
    Conflict(String),
    /// The addressed resource existed but is no longer available — a single-use, TTL-bounded
    /// pending signing session that has expired or been consumed (410, t57-S3). Distinct from a
    /// [`NotFound`](ApiError::NotFound) so the client can tell "never existed" from "expired".
    Gone(String),
    /// The request was well-formed but semantically invalid, e.g. a malformed date or a
    /// compliance-blocked seal (422).
    Unprocessable(String),
    /// A candidate password failed the strength policy (422, t68). Carries the per-rule failures so
    /// the client can point at exactly which requirements were not met. **Additive + self-contained:**
    /// no `contracts/**` fixture describes this body — the base `error` field is preserved and a
    /// `failed_rules` array is added alongside it.
    PasswordPolicy {
        /// Human-readable summary (mirrors the base `error` field).
        message: String,
        /// The requirements the candidate did not satisfy.
        failures: Vec<crate::password_policy::PasswordRuleFailure>,
    },
    /// Sealing was blocked by `Error`-severity compliance issues (422). The offending issues
    /// are returned as a structured `issues` array so the UI can cite each legal basis.
    ComplianceBlocked {
        /// Human-readable summary (mirrors the base `error` field).
        message: String,
        /// The blocking issues (all `Error` severity).
        issues: Vec<IssueView>,
    },
    /// Sealing carried unacknowledged `Warning`-severity issues (409). The warnings are
    /// returned as a structured `warnings` array so the UI can prompt for acknowledgement.
    WarningsNotAcknowledged {
        /// Human-readable summary (mirrors the base `error` field).
        message: String,
        /// The warnings awaiting acknowledgement.
        warnings: Vec<IssueView>,
    },
    /// An in-app Cartão de Cidadão PIN was rejected or the card is blocked (422, t67-e8). Carries a
    /// structured, machine-readable `pin_status` (`"wrong_pin"`/`"blocked"`) and a best-effort
    /// `tries_left` hint alongside the base `error` message. **Never carries the PIN** — the message
    /// and every field are reconstructed from the smartcard's guaranteed PIN-free error, so a wrong
    /// PIN can never leak through the body. Additive + self-contained (no `contracts/**` fixture).
    PinRejected {
        /// Human-readable, PIN-free summary (mirrors the base `error` field).
        message: String,
        /// `"wrong_pin"` (an incorrect PIN was presented) or `"blocked"` (the card is locked).
        pin_status: &'static str,
        /// Best-effort remaining-attempt hint (`"low"`/`"final_try"`/`"locked"`/`"unknown"`), or
        /// `None` when the card revealed nothing.
        tries_left: Option<&'static str>,
    },
    /// An unexpected internal failure, e.g. payload serialization (500). The string is a
    /// short, non-sensitive description safe to return to the caller.
    Internal(String),
    /// The node cannot serve this write right now (503). wp16 P0: it is not the cluster
    /// writer-leader — a follower, or a leader mid-failover / stepped down after losing the advisory
    /// lock. The client should retry; once a leader is elected it serves the write. The message is a
    /// short, non-sensitive PT string (never leaks internal state).
    Unavailable(String),
    /// A dependency upstream of the API failed — currently the certidão permanente registry
    /// consultation (network/HTTP failure, or a response that was not a recognisable
    /// certidão). Maps to `502 Bad Gateway` (contract §2.7).
    Upstream(String),
    /// An ata's markdown body was rejected — a malformed placeholder, a construct the frozen block
    /// set cannot represent, or an over-cap body (422, t74 §5).
    ///
    /// Structured rather than a plain [`Unprocessable`](ApiError::Unprocessable) because this is the
    /// one validation an operator hits *while typing*: `code` lets the editor branch without parsing
    /// prose, and `offset` lets it point at the character. Raised at edit time on purpose — the
    /// alternative is discovering it at the seal gate, which is exactly the surprise the design
    /// exists to prevent.
    InvalidActBody {
        /// Human-readable summary (mirrors the base `error` field).
        message: String,
        /// Stable machine-readable code (`unsupported_markdown`, `invalid_placeholder`, …).
        code: &'static str,
        /// Byte offset into the body source of the offending construct, when one applies.
        offset: Option<usize>,
    },
    /// **Tier 2 (t58).** An otherwise ordinary error carrying a *specific* [`code`](ApiError::code)
    /// in place of its variant-derived default. Status, message and structured body are taken
    /// entirely from `inner`, so wrapping an error changes nothing an operator, a contract fixture
    /// or a `body["error"]` assertion observes — only the `code` field moves.
    ///
    /// Build it with [`with_code`](ApiError::with_code), never by hand: that constructor enforces
    /// the two invariants this wrapper depends on (it never nests, and `Internal`/`Upstream` cannot
    /// be refined).
    ///
    /// **Pattern-matching on an [`ApiError`] must peel this first.** `matches!(e,
    /// ApiError::Conflict(_))` is `false` for a coded conflict, so every site that classifies an
    /// error *by variant* — as opposed to rendering it — must go through
    /// [`as_uncoded`](ApiError::as_uncoded) / [`into_uncoded`](ApiError::into_uncoded).
    ///
    /// **Every in-crate production classifier now does.** The audit behind this list was re-derived
    /// by tracking brace depth to decide whether each site sits inside a `#[cfg(test)]` module,
    /// rather than judging by proximity — the two earlier counts (15, then 8) were both wrong, in
    /// opposite directions, because one guessed from proximity and the other used a pattern that
    /// missed bare match arms and `ApiError` nested inside another enum's pattern.
    ///
    /// **10 production classifier expressions, in 6 files**, all now peeling — named by function
    /// rather than by line, because line numbers drift under concurrent work and a stale number is
    /// what let the previous version of this list go unchecked:
    ///
    /// - `documents.rs` — the two `render_persisted_act_document_model` `map_err`s, the model match
    ///   in `pdf_accessibility_evidence_for_act_document`, and the conflict guard in
    ///   `persist_created_user_template`
    /// - `signature.rs` — `cc_bridge_operation_error_code`, `cc_batch_doc_error_message`,
    ///   `resolve_cc_batch_doc`
    /// - `batch_signing.rs` / `zk_repository.rs` — their respective `api_error_message`
    /// - `smtp_settings.rs` — the `SendFailure::NotConfigured` arm
    /// - `lib.rs` — `clear_domain_memory_raw`'s warn-log filter
    ///
    /// Roughly 110 further by-variant matches live in `#[cfg(test)]` modules; they assert on
    /// uncoded errors and are correct as written.
    ///
    /// The hazard each of these carried is worth stating, because it is invisible: the usual shape
    /// is a `_ =>` arm degrading to a generic summary, so attaching a code upstream would have
    /// caused a **silent** loss of the server's honest message rather than anything the compiler
    /// could catch. A classifier that stops matching does not fail — it quietly gets vaguer.
    Coded {
        /// The error being refined. Never itself a `Coded` when built through `with_code`.
        inner: Box<ApiError>,
        /// The specific code, replacing `inner`'s variant-derived default.
        code: &'static str,
    },
}

impl From<chancela_templates::body_render::BodyRenderError> for ApiError {
    fn from(e: chancela_templates::body_render::BodyRenderError) -> Self {
        ApiError::InvalidActBody {
            message: e.to_string(),
            code: e.code(),
            offset: e.offset(),
        }
    }
}

/// The base JSON body every error renders to. `code` is additive next to the unchanged `error`
/// (t58): the client localises the former and keeps the latter as operator detail.
#[derive(Serialize)]
struct ErrorBody {
    error: String,
    code: &'static str,
}

/// Error body with a structured `issues` array (compliance-blocked seal).
#[derive(Serialize)]
struct ErrorWithIssues<'a> {
    error: &'a str,
    code: &'static str,
    issues: &'a [IssueView],
}

/// Error body with a structured `warnings` array (unacknowledged warnings).
#[derive(Serialize)]
struct ErrorWithWarnings<'a> {
    error: &'a str,
    code: &'static str,
    warnings: &'a [IssueView],
}

/// Error body with a structured `failed_rules` array (password strength policy, t68). Additive: the
/// base `error` field is preserved so a plain-envelope client still reads a message.
#[derive(Serialize)]
struct ErrorWithPasswordFailures<'a> {
    error: &'a str,
    code: &'static str,
    failed_rules: &'a [crate::password_policy::PasswordRuleFailure],
}

/// Error body for a rejected ata markdown body (t74). Additive: the base `error` field is preserved
/// and machine-readable fields are added alongside it. `offset` is a **byte** offset into the body
/// source, which is what lets the editor underline the offending construct in place rather than
/// telling the operator only that something, somewhere, is wrong.
#[derive(Serialize)]
struct ErrorWithBodyDiagnostics<'a> {
    error: &'a str,
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<usize>,
}

/// Error body for a rejected/blocked in-app Cartão de Cidadão PIN (t67-e8). Additive: the base
/// `error` field is preserved and PIN-free machine-readable fields are added alongside it. **Never
/// carries the PIN.**
#[derive(Serialize)]
struct ErrorWithPinStatus<'a> {
    error: &'a str,
    code: &'static str,
    pin_status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tries_left: Option<&'a str>,
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::InvalidNipc(_)
            | ApiError::Unprocessable(_)
            | ApiError::PasswordPolicy { .. }
            | ApiError::PinRejected { .. }
            | ApiError::InvalidActBody { .. }
            | ApiError::ComplianceBlocked { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Conflict(_) | ApiError::WarningsNotAcknowledged { .. } => {
                StatusCode::CONFLICT
            }
            ApiError::Gone(_) => StatusCode::GONE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Upstream(_) => StatusCode::BAD_GATEWAY,
            // A Tier-2 code refines the *description*, never the status.
            ApiError::Coded { inner, .. } => inner.status(),
        }
    }

    /// The stable, machine-readable code for this error (t58).
    ///
    /// **English, and it stays English** — this is an identifier, not copy. The client maps it to
    /// pt-PT through its own `apiError.<code>` catalog; the `error` field alongside keeps the full
    /// English detail.
    ///
    /// Two tiers share one namespace, told apart by the `http.` prefix:
    ///
    /// - **Tier 1 — `http.<variant>`.** The variant-derived default for the open-ended,
    ///   message-only variants. It means *"this site has not been given a specific code yet"*, so
    ///   the client renders an honest status-tier headline and surfaces the English detail rather
    ///   than inventing a cause for it. Every construction site has a code from the moment this
    ///   lands; none is left unresolvable.
    /// - **Tier 2 — a bare domain code** (`termo_stale_facts`, `already_exists.book`). Either
    ///   intrinsic to the variant, or attached at a call site via [`with_code`](ApiError::with_code).
    ///
    /// The `http.` prefix is **load-bearing, not cosmetic.** Bare-name code vocabularies already
    /// exist on this wire: `documents::TemplateErrorBody` emits `code: "conflict"` for a duplicate
    /// template id, which the client renders as *"Já existe um modelo com este identificador."*. A
    /// bare `conflict` default here would make every unrelated `409` on a template surface claim a
    /// duplicate id — a refusal explained by a cause that was never established, which is precisely
    /// the defect class this lane exists to remove. Prefixing keeps the generic tier unmistakable.
    ///
    /// Noun-shaped values never travel as parameters beside a code: if copy varies by noun it
    /// varies by *code* (`already_exists.book`, not `already_exists` + `{resource}`). pt-PT inflects
    /// for gender and number, so a noun dropped into a template sentence cannot be made to agree.
    pub fn code(&self) -> &'static str {
        match self {
            // Tier 2, attached at the call site.
            ApiError::Coded { code, .. } => code,

            // Tier 2, intrinsic: these variants exist *because* their cause is specific, so their
            // identity already is the code. Each is on the must-not-be-softened list — the client
            // gives them distinct copy and they never fall through to a generic status tier.
            ApiError::InvalidActBody { code, .. } => code,
            ApiError::InvalidNipc(_) => "invalid_nipc",
            ApiError::PasswordPolicy { .. } => "password_policy",
            ApiError::ComplianceBlocked { .. } => "compliance_blocked",
            ApiError::WarningsNotAcknowledged { .. } => "warnings_not_acknowledged",
            // Derived from the status the card itself reported, never guessed: a locked card is
            // terminal and must not read as retryable, so `blocked` gets its own code. An
            // unrecognised status falls back to the unqualified code rather than asserting a state
            // the card did not report.
            ApiError::PinRejected { pin_status, .. } => match *pin_status {
                "blocked" => "pin_rejected.blocked",
                "wrong_pin" => "pin_rejected.wrong_pin",
                _ => "pin_rejected",
            },

            // Tier 1 — variant-derived defaults.
            ApiError::NotFound => "http.not_found",
            ApiError::Unauthorized(_) => "http.unauthorized",
            // SECURITY — ONE code for every `403`, and it must stay that way.
            //
            // On the cross-user secret/attestation-key endpoints a `403` is returned uniformly for a
            // wrong password, an absent proof, *and* a target that does not exist, specifically so it
            // never enumerates users (see the `Forbidden` variant docs). `authz::FORBIDDEN` is the
            // same non-enumerating oracle for permission checks: it names neither the permission,
            // the scope, nor the resource.
            //
            // A `code` is a second, machine-readable channel carrying the same information. Splitting
            // it into `wrong_password` / `user_not_found` — the obvious "more precise errors are
            // better" refinement, and the whole point of this lane everywhere else — would rebuild
            // the enumeration oracle through the new channel and defeat the uniform message
            // entirely. **This is the one place where precision is the vulnerability.** Do not add
            // granularity here, and do not `with_code` those handlers apart.
            ApiError::Forbidden(_) => "http.forbidden",
            ApiError::TooManyRequests(_) => "http.too_many_requests",
            ApiError::Conflict(_) => "http.conflict",
            ApiError::Gone(_) => "http.gone",
            ApiError::Unprocessable(_) => "http.unprocessable",

            // Capped at the generic code on purpose. The message these carry is scrubbed off the
            // wire in `into_response` so internal state never leaks; a code that described the fault
            // any more finely would re-open exactly that channel. `with_code` refuses to refine them.
            ApiError::Internal(_) => "http.internal",
            ApiError::Unavailable(_) => "http.unavailable",
            ApiError::Upstream(_) => "http.upstream",
        }
    }

    /// Attach a **Tier-2** specific code, replacing the variant-derived default.
    ///
    /// Additive by construction: no constructor signature changes, and the status, the `error`
    /// message and any structured body are untouched — only `code` moves. Migration is therefore
    /// per-site and reversible.
    ///
    /// Two invariants are enforced here rather than left to convention:
    ///
    /// 1. **`Internal` and `Upstream` cannot be refined.** Their detail is deliberately scrubbed off
    ///    the wire; a caller-chosen code would describe the very fault the generic message hides.
    ///    The call is a no-op for them, so the cap cannot be lifted by forgetting about it.
    /// 2. **[`Coded`](ApiError::Coded) never nests.** Re-coding replaces the code, so peeling always
    ///    reaches the real variant.
    #[must_use]
    pub fn with_code(self, code: &'static str) -> ApiError {
        if matches!(self, ApiError::Internal(_) | ApiError::Upstream(_)) {
            return self;
        }
        match self {
            ApiError::Coded { inner, .. } => ApiError::Coded { inner, code },
            other => ApiError::Coded {
                inner: Box::new(other),
                code,
            },
        }
    }

    /// This error with any Tier-2 [`Coded`](ApiError::Coded) wrapper peeled off.
    ///
    /// **Every site that classifies an error by variant must go through this.** A `match` or
    /// `matches!` written against `ApiError::Conflict(_)` silently stops matching once that site's
    /// error is given a specific code, and the usual shape of such a classifier — a `_ =>` arm
    /// falling back to a generic summary — turns that into a *silent* loss of the honest message
    /// rather than a compile error.
    pub fn as_uncoded(&self) -> &ApiError {
        match self {
            ApiError::Coded { inner, .. } => inner.as_uncoded(),
            other => other,
        }
    }

    /// The owned counterpart of [`as_uncoded`](ApiError::as_uncoded), for classifiers that consume
    /// the error.
    #[must_use]
    pub fn into_uncoded(self) -> ApiError {
        match self {
            ApiError::Coded { inner, .. } => inner.into_uncoded(),
            other => other,
        }
    }

    fn message(&self) -> String {
        match self {
            ApiError::Coded { inner, .. } => inner.message(),
            ApiError::InvalidNipc(e) => e.to_string(),
            ApiError::NotFound => "resource not found".to_owned(),
            ApiError::Conflict(msg)
            | ApiError::Gone(msg)
            | ApiError::Unprocessable(msg)
            | ApiError::Unauthorized(msg)
            | ApiError::Forbidden(msg)
            | ApiError::TooManyRequests(msg)
            | ApiError::Internal(msg)
            | ApiError::Unavailable(msg)
            | ApiError::Upstream(msg) => msg.clone(),
            ApiError::ComplianceBlocked { message, .. }
            | ApiError::WarningsNotAcknowledged { message, .. }
            | ApiError::PinRejected { message, .. }
            | ApiError::InvalidActBody { message, .. }
            | ApiError::PasswordPolicy { message, .. } => message.clone(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        // t58: the stable machine code, resolved once. Taken from `self` rather than the peeled
        // error so a Tier-2 override wins over the variant default in every body shape below.
        let code = self.code();
        // Classify by variant through the Tier-2 wrapper, never around it: a coded `Unavailable` is
        // still a `503` that a retry will clear, and a coded `Internal` must still be scrubbed.
        let uncoded = self.as_uncoded();
        // wp16 P2: a cluster write-unavailable (`503`, not-leader / failover) advertises a short
        // `Retry-After` so clients/LBs back off and retry once a leader is (re-)elected. Computed
        // before `self` is matched/moved below.
        let retry_after = matches!(uncoded, ApiError::Unavailable(_));
        // t41 M6: log internal/upstream errors server-side with full detail, return a generic
        // message to the client so internal state never leaks through the wire.
        let message = match uncoded {
            ApiError::Internal(msg) => {
                eprintln!("chancela-api internal error: {msg}");
                "erro interno".to_owned()
            }
            ApiError::Upstream(msg) => {
                eprintln!("chancela-api upstream error: {msg}");
                "erro de gateway".to_owned()
            }
            other => other.message(),
        };
        match uncoded {
            ApiError::ComplianceBlocked { message, issues } => (
                status,
                Json(ErrorWithIssues {
                    error: message,
                    code,
                    issues,
                }),
            )
                .into_response(),
            ApiError::WarningsNotAcknowledged { message, warnings } => (
                status,
                Json(ErrorWithWarnings {
                    error: message,
                    code,
                    warnings,
                }),
            )
                .into_response(),
            ApiError::PasswordPolicy { message, failures } => (
                status,
                Json(ErrorWithPasswordFailures {
                    error: message,
                    code,
                    failed_rules: failures,
                }),
            )
                .into_response(),
            // `code` comes from the outer `self.code()`, which already resolves to this variant's
            // own diagnostic code — and to a Tier-2 override when one was attached.
            ApiError::InvalidActBody {
                message, offset, ..
            } => (
                status,
                Json(ErrorWithBodyDiagnostics {
                    error: message,
                    code,
                    offset: *offset,
                }),
            )
                .into_response(),
            ApiError::PinRejected {
                message,
                pin_status,
                tries_left,
            } => (
                status,
                Json(ErrorWithPinStatus {
                    error: message,
                    code,
                    pin_status,
                    tries_left: *tries_left,
                }),
            )
                .into_response(),
            _ => {
                let mut response =
                    (status, Json(ErrorBody { error: message, code })).into_response();
                if retry_after {
                    response.headers_mut().insert(
                        axum::http::header::RETRY_AFTER,
                        axum::http::HeaderValue::from_static("1"),
                    );
                }
                response
            }
        }
    }
}

impl From<NipcError> for ApiError {
    fn from(e: NipcError) -> Self {
        ApiError::InvalidNipc(e)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::Internal(format!("serialization failed: {e}"))
    }
}

/// An attestation crypto fault (a corrupt stored key blob, an RNG/serialization failure) is an
/// internal error (`500`). A *wrong password* is never this — the handler checks that with
/// [`verify_secret`](crate::attestation::verify_secret) and returns `401` itself.
impl From<crate::attestation::AttestationError> for ApiError {
    fn from(e: crate::attestation::AttestationError) -> Self {
        ApiError::Internal(e.to_string())
    }
}

/// Every `BookError` is a state-precondition failure → `409 Conflict` (contract §2.4/§2.5:
/// drafting into a non-open book, closing a non-open book, sealing across books).
impl From<BookError> for ApiError {
    fn from(e: BookError) -> Self {
        ApiError::Conflict(e.to_string())
    }
}

/// Default mapping for `SealError` used by book opening. The seal *handler* intercepts the
/// compliance variants itself to attach structured `issues`/`warnings` (contract §2.5), so
/// here they fall back to their plain-status forms.
impl From<SealError> for ApiError {
    fn from(e: SealError) -> Self {
        match e {
            SealError::Book(b) => b.into(),
            // Act-state failures at seal time (e.g. not `Signing`, wrong book) are conflicts.
            SealError::Act(a) => ApiError::Conflict(a.to_string()),
            SealError::ComplianceBlocked(msg) => ApiError::Unprocessable(msg),
            SealError::WarningsNotAcknowledged(msg) => ApiError::Conflict(msg),
            SealError::MissingManualSignatureOriginalReference => ApiError::Unprocessable(
                "manual_signature_original_reference is required for manual-signature sealing"
                    .to_owned(),
            ),
            SealError::InvalidSignatureEvidence(msg) => ApiError::Unprocessable(msg),
            SealError::Serialize(msg) => ApiError::Internal(msg),
        }
    }
}

/// Registry consultation failures (contract §2.7): a malformed access code is the caller's
/// fault (`422`); every upstream/recognition/config failure is a bad gateway (`502`). The
/// message never echoes the raw code — `RegistryError::InvalidCode` reports only the digit
/// count, so a mistyped secret cannot leak through the error body.
impl From<RegistryError> for ApiError {
    fn from(e: RegistryError) -> Self {
        let msg = e.to_string();
        match e {
            RegistryError::InvalidCode(_) => ApiError::Unprocessable(msg),
            // Upstream / Unrecognized / Config (and any future variant) → 502.
            _ => ApiError::Upstream(msg),
        }
    }
}

/// CAE auto-update failures on `POST /v1/cae/refresh` (contract §2.7): a fetch/parse/integrity
/// failure is a bad gateway (`502`); a config error (e.g. `CHANCELA_CAE_URL` unset) is a server
/// misconfiguration (`500`).
impl From<CaeError> for ApiError {
    fn from(e: CaeError) -> Self {
        let msg = e.to_string();
        match e {
            CaeError::Config(_) => ApiError::Internal(msg),
            // Http / Parse / Integrity (and any future variant) → 502.
            _ => ApiError::Upstream(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Every variant, so a new one cannot be added without deciding its code. Constructed rather
    /// than derived so the list is a *reviewed* inventory, not a restatement of the enum.
    fn every_variant() -> Vec<ApiError> {
        vec![
            ApiError::InvalidNipc(NipcError::Format("12".to_owned())),
            ApiError::NotFound,
            ApiError::Unauthorized("credenciais inválidas".to_owned()),
            ApiError::Forbidden(crate::authz::FORBIDDEN.to_owned()),
            ApiError::TooManyRequests("aguarde 30 segundos".to_owned()),
            ApiError::Conflict("book is not open".to_owned()),
            ApiError::Gone("pending signing session expired".to_owned()),
            ApiError::Unprocessable("date is malformed".to_owned()),
            ApiError::PasswordPolicy {
                message: "password too weak".to_owned(),
                failures: vec![],
            },
            ApiError::ComplianceBlocked {
                message: "sealing blocked".to_owned(),
                issues: vec![],
            },
            ApiError::WarningsNotAcknowledged {
                message: "warnings not acknowledged".to_owned(),
                warnings: vec![],
            },
            ApiError::PinRejected {
                message: "PIN incorreto".to_owned(),
                pin_status: "wrong_pin",
                tries_left: Some("low"),
            },
            ApiError::Internal("serialization failed".to_owned()),
            ApiError::Unavailable("not the writer-leader".to_owned()),
            ApiError::Upstream("registry unreachable".to_owned()),
            ApiError::InvalidActBody {
                message: "unsupported markdown".to_owned(),
                code: "unsupported_markdown",
                offset: Some(17),
            },
            ApiError::Conflict("stale facts".to_owned()).with_code("termo_stale_facts"),
        ]
    }

    async fn body_of(error: ApiError) -> Value {
        let bytes = axum::body::to_bytes(error.into_response().into_body(), usize::MAX)
            .await
            .expect("error response body");
        serde_json::from_slice(&bytes).expect("error body is JSON")
    }

    #[test]
    fn every_variant_yields_a_non_empty_code() {
        for error in every_variant() {
            let code = error.code();
            assert!(!code.is_empty(), "{error:?} has an empty code");
            assert_eq!(
                code.trim(),
                code,
                "{error:?} has a code with surrounding whitespace"
            );
            assert!(
                code.is_ascii() && !code.contains(' '),
                "{error:?} code {code:?} must be a bare ASCII identifier — it is English machine \
                 vocabulary, never user-facing copy"
            );
        }
    }

    /// The `http.` prefix is what keeps the generic tier from colliding with the bare-name domain
    /// vocabularies already on this wire (`TemplateErrorBody`'s `conflict`, the body diagnostics'
    /// `unsupported_markdown`). Losing it would let a generic `409` be rendered as a specific cause.
    #[test]
    fn tier_one_defaults_are_namespaced_and_tier_two_codes_are_not() {
        assert_eq!(ApiError::Conflict(String::new()).code(), "http.conflict");
        assert_eq!(ApiError::NotFound.code(), "http.not_found");
        assert_eq!(
            ApiError::Unprocessable(String::new()).code(),
            "http.unprocessable"
        );
        assert_eq!(ApiError::Gone(String::new()).code(), "http.gone");
        assert_eq!(
            ApiError::TooManyRequests(String::new()).code(),
            "http.too_many_requests"
        );
        // Specific codes are bare, so the two tiers are never confusable.
        for error in every_variant() {
            let code = error.code();
            assert_ne!(code, "conflict", "collides with TemplateErrorBody's code");
            if !code.starts_with("http.") {
                assert!(
                    !code.is_empty() && !code.starts_with('.'),
                    "{error:?} has a malformed specific code {code:?}"
                );
            }
        }
    }

    /// The scrubbing at the wire boundary exists so internal state never leaks. A code is a second
    /// channel for the same information, so it is capped too — structurally, not by convention.
    #[test]
    fn internal_and_upstream_codes_cannot_be_refined() {
        let internal = ApiError::Internal("private detail".to_owned()).with_code("db_pool_exhausted");
        assert_eq!(internal.code(), "http.internal");
        assert!(matches!(internal, ApiError::Internal(_)), "not even wrapped");

        let upstream = ApiError::Upstream("TSL host refused".to_owned()).with_code("tsl_refused");
        assert_eq!(upstream.code(), "http.upstream");
        assert!(matches!(upstream, ApiError::Upstream(_)));
    }

    /// Cross-user proof endpoints answer wrong-password, absent-proof and unknown-target with one
    /// indistinguishable `403`. The code must not become the channel that tells them apart.
    #[test]
    fn every_forbidden_shares_one_code() {
        let reasons = [
            crate::authz::FORBIDDEN,
            "palavra-passe atual incorreta",
            "no such user",
        ];
        let codes: Vec<&str> = reasons
            .iter()
            .map(|reason| ApiError::Forbidden((*reason).to_owned()).code())
            .collect();
        assert_eq!(
            codes,
            vec!["http.forbidden"; reasons.len()],
            "a per-reason 403 code would rebuild the user-enumeration oracle the uniform message \
             was written to prevent"
        );
    }

    #[test]
    fn pin_rejection_code_follows_the_card_reported_status() {
        let coded = |pin_status| {
            ApiError::PinRejected {
                message: "PIN".to_owned(),
                pin_status,
                tries_left: None,
            }
            .code()
        };
        assert_eq!(coded("blocked"), "pin_rejected.blocked");
        assert_eq!(coded("wrong_pin"), "pin_rejected.wrong_pin");
        // Never claims a state the card did not report.
        assert_eq!(coded("something_new"), "pin_rejected");
    }

    #[test]
    fn with_code_preserves_status_and_message_and_never_nests() {
        let plain = ApiError::Conflict("o livro já não corresponde".to_owned());
        let plain_status = plain.status();
        let coded = plain.with_code("termo_stale_facts");
        assert_eq!(coded.status(), plain_status);
        assert_eq!(coded.message(), "o livro já não corresponde");
        assert_eq!(coded.code(), "termo_stale_facts");

        let recoded = coded.with_code("termo_snapshot_render_drift");
        assert_eq!(recoded.code(), "termo_snapshot_render_drift");
        match &recoded {
            ApiError::Coded { inner, .. } => assert!(
                !matches!(**inner, ApiError::Coded { .. }),
                "re-coding must replace the code, not stack another wrapper"
            ),
            other => panic!("expected a coded error, got {other:?}"),
        }
        assert!(matches!(recoded.as_uncoded(), ApiError::Conflict(_)));
        assert!(matches!(recoded.into_uncoded(), ApiError::Conflict(_)));
    }

    /// Peeling is what keeps in-crate classifiers correct once a site is given a Tier-2 code, and it
    /// must survive a hand-built nest even though `with_code` cannot produce one.
    #[test]
    fn peeling_reaches_the_real_variant_through_nesting() {
        let nested = ApiError::Coded {
            inner: Box::new(ApiError::Coded {
                inner: Box::new(ApiError::NotFound),
                code: "inner",
            }),
            code: "outer",
        };
        assert!(matches!(nested.as_uncoded(), ApiError::NotFound));
        assert_eq!(nested.status(), StatusCode::NOT_FOUND);
        assert!(matches!(nested.into_uncoded(), ApiError::NotFound));
    }

    #[tokio::test]
    async fn every_body_shape_carries_error_and_code() {
        for error in every_variant() {
            let expected_code = error.code().to_owned();
            let debug = format!("{error:?}");
            let body = body_of(error).await;
            assert_eq!(
                body["code"], expected_code,
                "{debug} rendered without its code"
            );
            assert!(
                body["error"].as_str().is_some_and(|e| !e.is_empty()),
                "{debug} lost its operator-detail `error` string"
            );
        }
    }

    /// The structured payloads are richer than prose and several are on the must-not-be-softened
    /// list; adding `code` beside them must not disturb any of them.
    #[tokio::test]
    async fn structured_fields_survive_alongside_the_code() {
        let blocked = body_of(ApiError::ComplianceBlocked {
            message: "sealing blocked".to_owned(),
            issues: vec![],
        })
        .await;
        assert_eq!(blocked["code"], "compliance_blocked");
        assert!(blocked["issues"].is_array());

        let warnings = body_of(ApiError::WarningsNotAcknowledged {
            message: "warnings not acknowledged".to_owned(),
            warnings: vec![],
        })
        .await;
        assert_eq!(warnings["code"], "warnings_not_acknowledged");
        assert!(warnings["warnings"].is_array());

        let policy = body_of(ApiError::PasswordPolicy {
            message: "password too weak".to_owned(),
            failures: vec![],
        })
        .await;
        assert_eq!(policy["code"], "password_policy");
        assert!(policy["failed_rules"].is_array());

        let pin = body_of(ApiError::PinRejected {
            message: "cartão bloqueado".to_owned(),
            pin_status: "blocked",
            tries_left: Some("locked"),
        })
        .await;
        assert_eq!(pin["code"], "pin_rejected.blocked");
        assert_eq!(pin["pin_status"], "blocked");
        assert_eq!(pin["tries_left"], "locked");

        let body_diag = body_of(ApiError::InvalidActBody {
            message: "unsupported markdown".to_owned(),
            code: "unsupported_markdown",
            offset: Some(17),
        })
        .await;
        assert_eq!(body_diag["code"], "unsupported_markdown");
        assert_eq!(body_diag["offset"], 17);
    }

    /// `error` is the operator's diagnostic and the thing 184 in-tree assertions read. Scrubbing
    /// keeps its existing behaviour exactly, including through a Tier-2 wrapper.
    #[tokio::test]
    async fn scrubbed_variants_keep_their_generic_message_and_code() {
        let internal = body_of(ApiError::Internal("private detail".to_owned())).await;
        assert_eq!(internal["error"], "erro interno");
        assert_eq!(internal["code"], "http.internal");
        assert!(!internal.to_string().contains("private detail"));

        let upstream = body_of(ApiError::Upstream("TSL host refused".to_owned())).await;
        assert_eq!(upstream["error"], "erro de gateway");
        assert_eq!(upstream["code"], "http.upstream");
        assert!(!upstream.to_string().contains("TSL host refused"));
    }

    #[tokio::test]
    async fn a_coded_error_renders_its_inner_status_body_and_message() {
        let error =
            ApiError::Conflict("o documento já não corresponde ao livro".to_owned())
                .with_code("termo_stale_facts");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(body["error"], "o documento já não corresponde ao livro");
        assert_eq!(body["code"], "termo_stale_facts");
    }

    /// A `503` that a retry will clear must keep advertising that, code or no code.
    #[test]
    fn retry_after_survives_a_tier_two_code() {
        let plain = ApiError::Unavailable("not the writer-leader".to_owned()).into_response();
        assert_eq!(
            plain.headers().get(axum::http::header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("1"))
        );

        let coded = ApiError::Unavailable("not the writer-leader".to_owned())
            .with_code("not_writer_leader")
            .into_response();
        assert_eq!(coded.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            coded.headers().get(axum::http::header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("1"))
        );
    }
}
