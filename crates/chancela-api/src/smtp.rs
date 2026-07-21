//! A minimal, honest SMTP submission client (t23).
//!
//! This exists because the application had **no outbound mail capability at all** — the pre-existing
//! `crate::email` module is address *validation* only. Configuring SMTP is worthless if it cannot be
//! verified, so the settings surface ships with a test-send, and a test-send is worthless if it
//! collapses every failure into "could not send". Everything here is built around one requirement:
//! **surface the server's real answer**. When Postfix says `535 5.7.8 Error: authentication failed`
//! or `554 5.7.1 Relay access denied`, the operator sees that code and that text.
//!
//! ## What this implements — and what it refuses
//!
//! Deliberately narrow, because a test-send needs one message to one recipient, not a mail stack:
//!
//! - **Transport:** STARTTLS and implicit TLS. (Plaintext only on an explicit operator opt-in.)
//! - **Auth:** `AUTH PLAIN` and `AUTH LOGIN`. No XOAUTH2, CRAM-MD5, NTLM or SCRAM.
//! - **Message:** one sender, one recipient, plain-text UTF-8 body, base64 `Content-Transfer-
//!   Encoding` (so the payload is 7-bit clean and no line can breach the 998-octet limit, which is
//!   also why no dot-stuffing pass is needed), RFC 2047 headers.
//! - **Not implemented:** SMTPUTF8/EAI addresses, 8BITMIME, BINARYMIME, CHUNKING, pipelining,
//!   attachments, multiple recipients, DSN.
//!
//! Anything outside that set is **refused with a named error**, never negotiated on a guess — see
//! [`SmtpClient::reject_unimplemented`] and the `Configuration` arm of [`SmtpClient::authenticate`].
//! Silently mis-negotiating against an unfamiliar relay is the worst outcome for a self-hosted
//! product, because the operator debugging it is not the person who wrote this.
//!
//! ## Why not `lettre` — an honest note
//!
//! `lettre` is the de-facto Rust mail crate and would be a defensible choice; nothing in
//! `docs/dependency-management.md` forbids adding it. This is a judgement, not a policy outcome,
//! and the trade is:
//!
//! - **For hand-rolling:** `tokio` + `tokio-rustls` were already in `Cargo.lock` (via `reqwest`), so
//!   this adds zero crates to a tree that already carries a supply-chain pin gate, a digest-pinned
//!   image policy and a live RustSec exception. The surface actually needed is narrow (see above),
//!   and every reply code reaches the operator verbatim because nothing sits between them and it.
//! - **Against:** SMTP interop is genuinely subtle, and a bug here shows up as "works with our
//!   relay, fails with yours" — remote, self-hosted, and hard to debug. `lettre` has absorbed years
//!   of that. It also exposes reply codes on its error type, so the error-fidelity argument for
//!   hand-rolling is weaker than it first looks.
//!
//! The mitigation for the interop risk is the narrow scope above plus explicit refusal of
//! everything unimplemented. **If mail grows past a test-send — attachments, multiple recipients,
//! queuing, XOAUTH2 for Gmail/Microsoft 365 — switch to `lettre` rather than growing this.** That
//! is the point where the balance clearly flips.
//!
//! ## Transport security
//!
//! [`SmtpEncryption::StartTls`] is the default and [`SmtpEncryption::None`] is an explicit operator
//! choice. Two details that are easy to get wrong and are handled here:
//!
//! - **Downgrade refusal.** In `StartTls` mode, a server that does not advertise `STARTTLS` is a
//!   hard failure ([`SmtpFailureKind::TlsUnsupported`]). We never silently continue in the clear.
//! - **Response injection.** Before the TLS handshake we assert the read buffer is empty. A MITM can
//!   otherwise pipeline plaintext responses that get attributed to the encrypted session
//!   (CVE-2011-0411 and relatives).
//!
//! Credentials are only ever sent after encryption is established, unless the operator explicitly
//! selected [`SmtpEncryption::None`]; see [`SmtpClient::send`].

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use zeroize::Zeroizing;

/// How long any single network step (connect, handshake, command/reply) may take.
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

/// Guard against a hostile or broken server streaming an unbounded reply line.
const MAX_REPLY_LINE: u64 = 8 * 1024;

/// Guard against an unbounded multiline reply (a greeting/EHLO banner is a handful of lines).
const MAX_REPLY_LINES: usize = 128;

/// Guard against a chatty relay growing the diagnostic transcript without limit. A complete
/// submission conversation is well under this; anything beyond it is noise, not diagnosis.
const MAX_TRANSCRIPT_LINES: usize = 256;

// --- Configuration ---------------------------------------------------------------------------

/// The transport-security mode for an SMTP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpEncryption {
    /// Connect in the clear, then upgrade with `STARTTLS` before authenticating (submission port
    /// 587). The default: it is the modern submission norm and refuses to proceed if the server does
    /// not offer the upgrade.
    ///
    /// Renamed explicitly: `snake_case` would render this `start_tls`, but the wire form is the
    /// protocol keyword, `starttls`. See `encoding_matches_as_str` in the tests below, which pins
    /// serde and [`as_str`](Self::as_str) to each other so they cannot drift again.
    #[default]
    #[serde(rename = "starttls")]
    StartTls,
    /// Wrap the connection in TLS from the first byte ("SMTPS", port 465).
    ImplicitTls,
    /// No encryption at all. Credentials and message content travel in the clear. Only ever selected
    /// deliberately, for a trusted-network relay that offers nothing else.
    None,
}

impl SmtpEncryption {
    /// The stable wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StartTls => "starttls",
            Self::ImplicitTls => "implicit_tls",
            Self::None => "none",
        }
    }

    /// Whether this mode ever puts the session inside TLS.
    pub fn is_encrypted(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Everything needed to open one SMTP session. Built by the caller from the mail settings plus the
/// password read out of the credential store.
pub struct SmtpClient {
    /// Relay hostname (also the TLS certificate name).
    pub host: String,
    /// Relay port.
    pub port: u16,
    /// Transport-security mode.
    pub encryption: SmtpEncryption,
    /// AUTH username, or `None` for an unauthenticated relay.
    pub username: Option<String>,
    /// AUTH password. Held zeroizing; never logged, never rendered into an error.
    pub password: Option<Zeroizing<String>>,
    /// The name announced in `EHLO`.
    pub helo_name: String,
}

/// One outbound message.
pub struct SmtpMessage {
    /// Envelope sender (`MAIL FROM`) and `From:` address.
    pub from_address: String,
    /// Optional display name for the `From:` header.
    pub from_name: Option<String>,
    /// Envelope recipient (`RCPT TO`) and `To:` address.
    pub to_address: String,
    /// `Subject:` header (encoded per RFC 2047 when it is not pure ASCII).
    pub subject: String,
    /// UTF-8 plain-text body. **Always required, never a fallback afterthought**: many clients and
    /// most security gateways strip or refuse HTML-only mail, and this is also the accessible
    /// version. When `html_body` is set this becomes the first part of a `multipart/alternative`.
    pub body: String,
    /// Optional UTF-8 HTML body. When present the message is rendered as `multipart/alternative`
    /// with `body` first and this second, which is the order RFC 2046 §5.1.4 requires: least
    /// faithful first, so a client that understands only `text/plain` shows the text part.
    pub html_body: Option<String>,
    /// RFC 3339/2822 `Date:` value, supplied by the caller so this module stays clock-free.
    pub date: String,
    /// The `Message-ID:` value without angle brackets.
    pub message_id: String,
}

// --- Failure reporting -----------------------------------------------------------------------

/// Where in the session a failure happened. Reported to the operator verbatim, because "it failed at
/// AUTH" and "it failed at RCPT TO" point at completely different fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpStage {
    /// Resolving the host and opening the TCP connection.
    Connect,
    /// The TLS handshake (implicit, or post-`STARTTLS`).
    Tls,
    /// Reading the server's opening banner.
    Greeting,
    /// The `EHLO` handshake.
    Ehlo,
    /// The `STARTTLS` command. Renamed for the same reason as
    /// [`SmtpEncryption::StartTls`]: the wire form is the protocol keyword, not `start_tls`.
    #[serde(rename = "starttls")]
    StartTls,
    /// `AUTH` — a rejection here is bad credentials, not a bad address.
    Auth,
    /// `MAIL FROM` — a rejection here is usually a sender the relay will not accept.
    MailFrom,
    /// `RCPT TO` — a rejection here is usually relay denial or an unknown recipient.
    RcptTo,
    /// The `DATA` command and the message body.
    Data,
    /// `QUIT`.
    Quit,
}

impl SmtpStage {
    /// The stable wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Greeting => "greeting",
            Self::Ehlo => "ehlo",
            Self::StartTls => "starttls",
            Self::Auth => "auth",
            Self::MailFrom => "mail_from",
            Self::RcptTo => "rcpt_to",
            Self::Data => "data",
            Self::Quit => "quit",
        }
    }
}

/// What kind of failure it was. The operator's next action differs per kind, so these are not
/// collapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpFailureKind {
    /// The hostname did not resolve.
    Dns,
    /// The host resolved but the connection was refused, reset, or unroutable.
    Unreachable,
    /// A TLS handshake failure: untrusted/expired/mismatched certificate, or no protocol overlap.
    Tls,
    /// `STARTTLS` was required but the server did not advertise it.
    TlsUnsupported,
    /// A step exceeded its timeout.
    Timeout,
    /// The server answered, but with an error reply. `code`/`enhanced_code`/`detail` carry it.
    Rejected,
    /// The server's answer did not parse as SMTP, or the connection dropped mid-session.
    Protocol,
    /// The configuration itself is unusable (e.g. AUTH required but the server offers no mechanism
    /// we implement).
    Configuration,
}

impl SmtpFailureKind {
    /// The stable wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Unreachable => "unreachable",
            Self::Tls => "tls",
            Self::TlsUnsupported => "tls_unsupported",
            Self::Timeout => "timeout",
            Self::Rejected => "rejected",
            Self::Protocol => "protocol",
            Self::Configuration => "configuration",
        }
    }
}

/// A structured SMTP failure. Carries the server's real reply so an operator debugging mail is not
/// guessing. **Never carries the password** — the only server-derived text included is the reply
/// text, and the only client-derived text is the command verb, never its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpFailure {
    /// Where it failed.
    pub stage: SmtpStage,
    /// What kind of failure it was.
    pub kind: SmtpFailureKind,
    /// The SMTP reply code (e.g. `535`, `554`), when the server actually replied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
    /// The RFC 3463 enhanced status code (e.g. `5.7.1`), when the reply carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enhanced_code: Option<String>,
    /// The server's reply text verbatim, or the OS/TLS error text when the server never replied.
    pub detail: String,
    /// Whether the session was already inside TLS when it failed. Stamped centrally in
    /// [`SmtpClient::send`] from the live session, not guessed from the stage — a rejection at
    /// `RCPT TO` on an encrypted session and the same rejection in the clear are different facts,
    /// and reporting the second as the first would be a lie about how the password travelled.
    pub tls: bool,
}

impl SmtpFailure {
    fn new(stage: SmtpStage, kind: SmtpFailureKind, detail: impl Into<String>) -> Self {
        SmtpFailure {
            stage,
            kind,
            code: None,
            enhanced_code: None,
            detail: detail.into(),
            tls: false,
        }
    }

    fn from_reply(stage: SmtpStage, reply: &SmtpReply) -> Self {
        SmtpFailure {
            stage,
            kind: SmtpFailureKind::Rejected,
            code: Some(reply.code),
            enhanced_code: reply.enhanced_code.clone(),
            detail: reply.text.clone(),
            tls: false,
        }
    }

    fn from_io(stage: SmtpStage, err: &io::Error) -> Self {
        let kind = match err.kind() {
            io::ErrorKind::TimedOut => SmtpFailureKind::Timeout,
            io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::AddrNotAvailable => SmtpFailureKind::Unreachable,
            _ if stage == SmtpStage::Tls => SmtpFailureKind::Tls,
            _ if stage == SmtpStage::Connect => SmtpFailureKind::Unreachable,
            _ => SmtpFailureKind::Protocol,
        };
        SmtpFailure::new(stage, kind, err.to_string())
    }

    /// A one-line operator-facing summary: the code, the enhanced code, and the server's text.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        if let Some(code) = self.code {
            out.push_str(&code.to_string());
            if let Some(enhanced) = &self.enhanced_code {
                out.push(' ');
                out.push_str(enhanced);
            }
            out.push_str(": ");
        }
        out.push_str(&self.detail);
        out
    }
}

/// A successful send: what the relay accepted, and under what protection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpDelivery {
    /// Whether the session actually ran inside TLS.
    pub tls: bool,
    /// Whether the session authenticated.
    pub authenticated: bool,
    /// The relay's final `250` reply to the message body (often carries its queue id).
    pub accepted_detail: String,
}

// --- Diagnostic trace ---------------------------------------------------------------------------

/// How a single protocol stage ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpStepOutcome {
    /// The stage completed and the server was happy.
    Ok,
    /// The stage was attempted and failed. This is the stage the operator should look at.
    Failed,
    /// The stage was not attempted at all, because the configuration does not use it (e.g.
    /// `STARTTLS` on an implicit-TLS session, or `AUTH` with no username). Recorded rather than
    /// omitted so the timeline shows the whole protocol, not just the parts that ran.
    Skipped,
    /// The *client* refused to proceed — an unimplemented AUTH mechanism, a non-ASCII envelope
    /// address needing SMTPUTF8, or a STARTTLS downgrade. Distinct from `Failed` because nothing is
    /// wrong with the relay: the fix is on this side.
    Refused,
}

// Deliberately no `as_str` here, unlike the neighbouring enums. Theirs exist because something
// server-side formats them into a message (`SmtpEncryption` into the test email, `SmtpStage` into a
// send failure's text); nothing formats this one — its only consumer is the TypeScript union that
// renders it. A second unused spelling of the wire form would be one more thing that can silently
// disagree with serde, which is exactly the `start_tls`/`starttls` trap t23 fell into. The encoding
// is pinned against literals in `step_outcome_serde_encoding_is_stable` instead.

/// One protocol stage in the timeline, with its outcome, the server's own reply, and its duration.
///
/// Timing is per-stage on purpose: a relay that refuses in 3ms and a relay that swallows the
/// connection for 20s are completely different problems, and a single "failed" hides that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpTraceStep {
    /// Which stage this is.
    pub stage: SmtpStage,
    /// How it ended.
    pub outcome: SmtpStepOutcome,
    /// The SMTP reply code the server gave for this stage, when it replied at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
    /// The RFC 3463 enhanced status code, when the reply carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enhanced_code: Option<String>,
    /// The server's reply text **verbatim**, or — for `Skipped`/`Refused` — this client's own
    /// explanation of why it did not proceed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Milliseconds from the start of the session to the moment this stage began.
    pub started_ms: u64,
    /// How long the stage took, in milliseconds.
    pub duration_ms: u64,
}

/// What the TLS handshake actually negotiated. Populated only when a handshake succeeded.
///
/// "Is it encrypted?" is a yes/no an operator can already see; *which* protocol version and *whose*
/// certificate is what distinguishes a working relay from one that is quietly serving a self-signed
/// certificate or a captive-portal interception box.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SmtpTlsDetail {
    /// The negotiated protocol version, e.g. `TLSv1.3`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// The negotiated cipher suite, e.g. `TLS13_AES_256_GCM_SHA384`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// The leaf certificate's subject distinguished name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_subject: Option<String>,
    /// The leaf certificate's issuer distinguished name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_issuer: Option<String>,
}

/// Who said a transcript line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTranscriptDirection {
    /// Sent by this client.
    Client,
    /// Received from the relay.
    Server,
}

/// One line of the SMTP conversation, as it would appear in a `swaks`/`telnet` transcript.
///
/// **Client lines are never verbatim.** See [`Recorder`] for the two independent mechanisms that
/// keep the password out of this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpTranscriptLine {
    /// Who said it.
    pub direction: SmtpTranscriptDirection,
    /// The line. Redacted where credentials would otherwise appear.
    pub text: String,
    /// Milliseconds from the start of the session.
    pub at_ms: u64,
}

/// The full diagnostic record of one SMTP session — enough to debug a relay without server access.
///
/// This is produced on **both** success and failure. A send that works but takes 19 seconds at
/// `RCPT TO`, or one that silently ran without TLS, is worth seeing too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpTrace {
    /// The relay hostname as configured.
    pub host: String,
    /// The relay port as configured.
    pub port: u16,
    /// The peer address the TCP connection actually landed on, e.g. `10.0.0.5:587`. This is the
    /// resolution result: a hostname that resolves somewhere unexpected is invisible otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_address: Option<String>,
    /// The configured transport-security mode.
    pub encryption: SmtpEncryption,
    /// The name announced in `EHLO`.
    pub helo_name: String,
    /// Whether TLS was **actually** established, as observed on the live session — not what the
    /// configuration asked for.
    pub tls_established: bool,
    /// What the handshake negotiated, when one succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<SmtpTlsDetail>,
    /// The capabilities the relay advertised in its (last) `EHLO` response, verbatim.
    pub advertised_capabilities: Vec<String>,
    /// The AUTH mechanism this client chose, e.g. `PLAIN`. `None` when no authentication ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_mechanism: Option<String>,
    /// The protocol timeline, in order.
    pub steps: Vec<SmtpTraceStep>,
    /// The conversation, redacted.
    pub transcript: Vec<SmtpTranscriptLine>,
    /// Total session duration in milliseconds.
    pub total_ms: u64,
}

/// Builds an [`SmtpTrace`] as the session runs.
///
/// ## How the password is kept out — two independent mechanisms
///
/// 1. **Structural.** Credential-bearing lines never reach the recorder in the first place. They
///    are written through [`Session::command_redacted`], which records a fixed `&'static str`
///    placeholder and has **no parameter** through which the real line could be passed. The
///    recorder therefore only ever receives either a literal, or a line built from non-secret
///    configuration (the EHLO name, the envelope addresses).
/// 2. **Scrubbing, as defence in depth.** The recorder additionally holds the password and its
///    base64 encodings as needles and replaces them in *every* line it stores, in both directions.
///    This layer exists for the pathological case mechanism 1 cannot cover: a broken or hostile
///    relay echoing the credential back in its own reply text, which is otherwise recorded
///    verbatim by design.
///
/// The needles live only in the recorder, in [`Zeroizing`] buffers, are never serialized (they are
/// not part of [`SmtpTrace`]), and the hand-written [`std::fmt::Debug`] below keeps them out of
/// panic messages and log lines.
struct Recorder {
    started: Instant,
    /// Secret substrings to replace wherever they appear. Never serialized, never printed.
    needles: Vec<Zeroizing<String>>,
    steps: Vec<SmtpTraceStep>,
    transcript: Vec<SmtpTranscriptLine>,
    tls: Option<SmtpTlsDetail>,
    resolved_address: Option<String>,
    advertised_capabilities: Vec<String>,
    auth_mechanism: Option<String>,
}

// Derived `Debug` would print the needles. Written by hand so the plaintext cannot reach a log line
// or a panic message through the recorder.
impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field(
                "needles",
                &format_args!("<{} redacted>", self.needles.len()),
            )
            .field("steps", &self.steps.len())
            .field("transcript", &self.transcript.len())
            .finish_non_exhaustive()
    }
}

/// What a redacted secret is replaced with, in both the transcript and any scrubbed reply text.
const REDACTED: &str = "<redacted>";

impl Recorder {
    /// Build a recorder, deriving the scrub needles from the credentials this session will use.
    ///
    /// The base64 forms matter as much as the plaintext: on the wire the password only ever appears
    /// base64-encoded, so a relay echoing "what you sent me" echoes the encoding, not the password.
    fn new(username: Option<&str>, password: Option<&Zeroizing<String>>) -> Self {
        let mut needles: Vec<Zeroizing<String>> = Vec::new();
        if let Some(password) = password.filter(|p| !p.is_empty()) {
            // The plaintext.
            needles.push(Zeroizing::new(password.to_string()));
            // `AUTH LOGIN`'s second challenge response: base64 of the password alone.
            needles.push(Zeroizing::new(BASE64.encode(password.as_bytes())));
            // `AUTH PLAIN`'s single blob: base64 of NUL authcid NUL passwd.
            if let Some(username) = username {
                let mut raw = Zeroizing::new(Vec::new());
                raw.push(0);
                raw.extend_from_slice(username.as_bytes());
                raw.push(0);
                raw.extend_from_slice(password.as_bytes());
                needles.push(Zeroizing::new(BASE64.encode(&*raw)));
            }
        }
        Recorder {
            started: Instant::now(),
            needles,
            steps: Vec::new(),
            transcript: Vec::new(),
            tls: None,
            resolved_address: None,
            advertised_capabilities: Vec::new(),
            auth_mechanism: None,
        }
    }

    /// Milliseconds since the session began.
    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    /// Replace every secret needle in `text`. Applied to everything the recorder stores, in both
    /// directions — see the mechanism-2 note on [`Recorder`].
    fn scrub(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for needle in &self.needles {
            if !needle.is_empty() && out.contains(needle.as_str()) {
                out = out.replace(needle.as_str(), REDACTED);
            }
        }
        out
    }

    fn line(&mut self, direction: SmtpTranscriptDirection, text: &str) {
        // Bound the transcript the same way replies are bounded, so a chatty relay cannot grow the
        // response without limit.
        if self.transcript.len() >= MAX_TRANSCRIPT_LINES {
            return;
        }
        let at_ms = self.elapsed_ms();
        self.transcript.push(SmtpTranscriptLine {
            direction,
            text: self.scrub(text),
            at_ms,
        });
    }

    /// Record a stage that succeeded.
    fn ok(&mut self, stage: SmtpStage, since: Instant, reply: Option<&SmtpReply>) {
        self.push_step(
            stage,
            SmtpStepOutcome::Ok,
            since,
            reply.map(|r| r.code),
            reply.and_then(|r| r.enhanced_code.clone()),
            reply.map(|r| r.text.clone()),
        );
    }

    /// Record a stage that failed, carrying the server's own code and text through unchanged.
    fn fail(&mut self, stage: SmtpStage, since: Instant, failure: &SmtpFailure) {
        let outcome = match failure.kind {
            // A `Configuration` failure is this client declining, not the relay erroring.
            SmtpFailureKind::Configuration | SmtpFailureKind::TlsUnsupported => {
                SmtpStepOutcome::Refused
            }
            _ => SmtpStepOutcome::Failed,
        };
        self.push_step(
            stage,
            outcome,
            since,
            failure.code,
            failure.enhanced_code.clone(),
            Some(failure.detail.clone()),
        );
    }

    /// Record a stage that was never attempted, and why.
    fn skipped(&mut self, stage: SmtpStage, why: &str) {
        let started_ms = self.elapsed_ms();
        self.steps.push(SmtpTraceStep {
            stage,
            outcome: SmtpStepOutcome::Skipped,
            code: None,
            enhanced_code: None,
            detail: Some(why.to_owned()),
            started_ms,
            duration_ms: 0,
        });
    }

    fn push_step(
        &mut self,
        stage: SmtpStage,
        outcome: SmtpStepOutcome,
        since: Instant,
        code: Option<u16>,
        enhanced_code: Option<String>,
        detail: Option<String>,
    ) {
        let duration_ms = since.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let started_ms = self.elapsed_ms().saturating_sub(duration_ms);
        self.steps.push(SmtpTraceStep {
            stage,
            outcome,
            code,
            enhanced_code,
            detail: detail.map(|d| self.scrub(&d)),
            started_ms,
            duration_ms,
        });
    }

    /// Freeze into the serializable trace. Consumes the needles with it.
    fn finish(self, client: &SmtpClient, tls_established: bool) -> SmtpTrace {
        let total_ms = self.elapsed_ms();
        SmtpTrace {
            host: client.host.clone(),
            port: client.port,
            resolved_address: self.resolved_address,
            encryption: client.encryption,
            helo_name: client.helo_name.clone(),
            tls_established,
            tls: self.tls,
            advertised_capabilities: self.advertised_capabilities,
            auth_mechanism: self.auth_mechanism,
            steps: self.steps,
            transcript: self.transcript,
            total_ms,
        }
    }
}

// --- Reply parsing ---------------------------------------------------------------------------

/// One parsed SMTP reply (possibly multiline).
#[derive(Debug, Clone)]
struct SmtpReply {
    code: u16,
    enhanced_code: Option<String>,
    /// The reply text with the code prefixes stripped, lines joined by `; `.
    text: String,
    /// The raw text lines, used to read EHLO capabilities.
    lines: Vec<String>,
}

impl SmtpReply {
    fn is_positive(&self) -> bool {
        (200..400).contains(&self.code)
    }
}

/// Pull an RFC 3463 enhanced status code (`5.7.1`) off the front of a reply line, if present.
fn parse_enhanced_code(text: &str) -> Option<String> {
    let token = text.split_whitespace().next()?;
    let mut parts = token.split('.');
    let class = parts.next()?;
    let subject = parts.next()?;
    let detail = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !matches!(class, "2" | "4" | "5") {
        return None;
    }
    let numeric = |s: &str| !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit());
    (numeric(subject) && numeric(detail)).then(|| token.to_owned())
}

// --- The duplex stream (plain, or upgraded to TLS) ---------------------------------------------

/// The session's byte stream. An enum rather than a trait object because `STARTTLS` has to reclaim
/// the concrete [`TcpStream`] to hand it to the TLS connector.
enum SmtpStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    /// Transient placeholder held only while `STARTTLS` moves the `TcpStream` into the TLS
    /// connector. It is never observed by a read or write: the upgrade either replaces it with
    /// `Tls`, or the handshake fails and the whole session is dropped. Every I/O impl below fails
    /// closed on it rather than silently doing nothing.
    Upgrading,
}

impl AsyncRead for SmtpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            SmtpStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            SmtpStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
            SmtpStream::Upgrading => std::task::Poll::Ready(Err(upgrading_io_error())),
        }
    }
}

/// The error every I/O impl returns for the transient `Upgrading` placeholder.
fn upgrading_io_error() -> io::Error {
    io::Error::other("internal: SMTP stream used while a STARTTLS upgrade was in flight")
}

impl AsyncWrite for SmtpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            SmtpStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            SmtpStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
            SmtpStream::Upgrading => std::task::Poll::Ready(Err(upgrading_io_error())),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            SmtpStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            SmtpStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
            SmtpStream::Upgrading => std::task::Poll::Ready(Err(upgrading_io_error())),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            SmtpStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            SmtpStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
            SmtpStream::Upgrading => std::task::Poll::Ready(Err(upgrading_io_error())),
        }
    }
}

/// The live session: a buffered duplex plus whether it is currently encrypted.
struct Session {
    stream: BufReader<SmtpStream>,
    tls: bool,
    /// The diagnostic recorder. It lives inside the session so the two I/O chokepoints
    /// ([`Session::read_reply`] and [`Session::write_line`]) are the *only* places a transcript
    /// line can be created — there is no third path that could append an unredacted one.
    rec: Recorder,
}

impl Session {
    /// Read one (possibly multiline) reply.
    async fn read_reply(&mut self, stage: SmtpStage) -> Result<SmtpReply, SmtpFailure> {
        let mut code: Option<u16> = None;
        let mut lines: Vec<String> = Vec::new();
        loop {
            if lines.len() >= MAX_REPLY_LINES {
                return Err(SmtpFailure::new(
                    stage,
                    SmtpFailureKind::Protocol,
                    "the server sent an implausibly long multiline reply",
                ));
            }
            let mut line = String::new();
            let read = tokio::time::timeout(
                STEP_TIMEOUT,
                (&mut self.stream).take(MAX_REPLY_LINE).read_line(&mut line),
            )
            .await
            .map_err(|_| {
                SmtpFailure::new(
                    stage,
                    SmtpFailureKind::Timeout,
                    format!(
                        "timed out after {}s waiting for a reply",
                        STEP_TIMEOUT.as_secs()
                    ),
                )
            })?
            .map_err(|e| SmtpFailure::from_io(stage, &e))?;
            if read == 0 {
                return Err(SmtpFailure::new(
                    stage,
                    SmtpFailureKind::Protocol,
                    "the server closed the connection without replying",
                ));
            }
            let line = line.trim_end_matches(['\r', '\n']);
            // The sole place a server line enters the transcript, so the scrub in `Recorder::line`
            // cannot be bypassed. Recorded before parsing: an unparseable reply is exactly the case
            // where seeing the raw bytes matters most.
            self.rec.line(SmtpTranscriptDirection::Server, line);
            if line.len() < 3 {
                return Err(SmtpFailure::new(
                    stage,
                    SmtpFailureKind::Protocol,
                    format!("unparseable SMTP reply {line:?}"),
                ));
            }
            let (digits, rest) = line.split_at(3);
            let parsed: u16 = digits.parse().map_err(|_| {
                SmtpFailure::new(
                    stage,
                    SmtpFailureKind::Protocol,
                    format!("unparseable SMTP reply code in {line:?}"),
                )
            })?;
            if *code.get_or_insert(parsed) != parsed {
                return Err(SmtpFailure::new(
                    stage,
                    SmtpFailureKind::Protocol,
                    "the server changed reply code mid-response",
                ));
            }
            let (more, text) = match rest.as_bytes().first() {
                None => (false, ""),
                Some(b'-') => (true, &rest[1..]),
                Some(b' ') => (false, &rest[1..]),
                Some(_) => {
                    return Err(SmtpFailure::new(
                        stage,
                        SmtpFailureKind::Protocol,
                        format!("unparseable SMTP reply separator in {line:?}"),
                    ));
                }
            };
            lines.push(text.to_owned());
            if !more {
                break;
            }
        }
        let code = code.unwrap_or_default();
        let enhanced_code = lines.first().and_then(|l| parse_enhanced_code(l));
        // Strip the enhanced code from the operator-facing text so it is not printed twice.
        let text = lines
            .iter()
            .enumerate()
            .map(|(i, l)| match (i, &enhanced_code) {
                (0, Some(enhanced)) => l
                    .strip_prefix(enhanced.as_str())
                    .map(str::trim_start)
                    .unwrap_or(l),
                _ => l.as_str(),
            })
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("; ");
        Ok(SmtpReply {
            code,
            enhanced_code,
            text,
            lines,
        })
    }

    /// Write a line and read the reply, recording the line in the transcript verbatim.
    ///
    /// **Only for lines built from non-secret data** — the EHLO name, the envelope addresses, and
    /// bare verbs. Anything carrying a credential goes through [`command_redacted`] instead.
    ///
    /// [`command_redacted`]: Session::command_redacted
    async fn command(&mut self, stage: SmtpStage, line: &str) -> Result<SmtpReply, SmtpFailure> {
        self.rec.line(SmtpTranscriptDirection::Client, line);
        self.write_line(stage, line).await?;
        self.read_reply(stage).await
    }

    /// Write a credential-bearing line, recording `shown` in its place.
    ///
    /// `shown` is `&'static str`, and that is the point rather than an incidental choice: the
    /// password reaches this process at runtime, out of the credential store, so it can never be a
    /// `'static` string. The type therefore makes "record the real line" unexpressible here — the
    /// only thing this method can put in the transcript is a literal written in this file.
    async fn command_redacted(
        &mut self,
        stage: SmtpStage,
        line: &str,
        shown: &'static str,
    ) -> Result<SmtpReply, SmtpFailure> {
        self.rec.line(SmtpTranscriptDirection::Client, shown);
        self.write_line(stage, line).await?;
        self.read_reply(stage).await
    }

    /// Write a raw line **without** recording it. The transcript entry, if any, is the caller's
    /// responsibility — used for the message body, which is bulk content rather than conversation.
    async fn write_line(&mut self, stage: SmtpStage, line: &str) -> Result<(), SmtpFailure> {
        let payload = format!("{line}\r\n");
        tokio::time::timeout(STEP_TIMEOUT, async {
            self.stream.write_all(payload.as_bytes()).await?;
            self.stream.flush().await
        })
        .await
        .map_err(|_| {
            SmtpFailure::new(
                stage,
                SmtpFailureKind::Timeout,
                format!(
                    "timed out after {}s sending a command",
                    STEP_TIMEOUT.as_secs()
                ),
            )
        })?
        .map_err(|e| SmtpFailure::from_io(stage, &e))
    }

    /// Require a positive reply, or fail with the server's actual code and text.
    fn expect_positive(reply: SmtpReply, stage: SmtpStage) -> Result<SmtpReply, SmtpFailure> {
        if reply.is_positive() {
            Ok(reply)
        } else {
            Err(SmtpFailure::from_reply(stage, &reply))
        }
    }
}

// --- Capabilities ------------------------------------------------------------------------------

/// What the server advertised in its `EHLO` response.
#[derive(Debug, Default)]
struct Capabilities {
    starttls: bool,
    auth_plain: bool,
    auth_login: bool,
}

impl Capabilities {
    fn parse(lines: &[String]) -> Self {
        let mut caps = Capabilities::default();
        // The first EHLO line is the greeting, not a capability.
        for line in lines.iter().skip(1) {
            let mut tokens = line.split_whitespace();
            let Some(keyword) = tokens.next() else {
                continue;
            };
            if keyword.eq_ignore_ascii_case("STARTTLS") {
                caps.starttls = true;
            } else if keyword.eq_ignore_ascii_case("AUTH") {
                for mech in tokens {
                    if mech.eq_ignore_ascii_case("PLAIN") {
                        caps.auth_plain = true;
                    } else if mech.eq_ignore_ascii_case("LOGIN") {
                        caps.auth_login = true;
                    }
                }
            }
        }
        caps
    }
}

// --- The session ---------------------------------------------------------------------------

impl SmtpClient {
    /// Open a session, deliver `message`, and close cleanly.
    ///
    /// Ordering is security-relevant: TLS is established (and, in `StartTls` mode, *required*)
    /// before `AUTH` is ever sent. The only path that transmits credentials in the clear is the one
    /// where the operator explicitly chose [`SmtpEncryption::None`].
    pub async fn send(&self, message: &SmtpMessage) -> Result<SmtpDelivery, SmtpFailure> {
        self.send_traced(message).await.0
    }

    /// [`send`](Self::send), also returning the full diagnostic [`SmtpTrace`].
    ///
    /// The trace is produced on **both** outcomes, because a send that succeeds slowly, or succeeds
    /// without TLS, is as worth seeing as one that fails. This is what the settings test-send calls;
    /// `send` is the convenience wrapper for callers that only want the result.
    pub async fn send_traced(
        &self,
        message: &SmtpMessage,
    ) -> (Result<SmtpDelivery, SmtpFailure>, SmtpTrace) {
        self.send_traced_with_roots(message, &NativeRoots).await
    }

    /// [`send`](Self::send) with the TLS trust anchors supplied explicitly — see [`TlsRoots`].
    ///
    /// Private to this module, so `send` is the only way in from anywhere else in the crate. The
    /// ordering below is the property under test and is identical on both paths: nothing that
    /// identifies the account or the correspondents is written until the session is encrypted.
    async fn send_traced_with_roots(
        &self,
        message: &SmtpMessage,
        roots: &dyn TlsRoots,
    ) -> (Result<SmtpDelivery, SmtpFailure>, SmtpTrace) {
        let mut rec = Recorder::new(self.username.as_deref(), self.password.as_ref());

        // Refuse before opening a socket, rather than negotiate something we did not implement.
        let since = Instant::now();
        if let Err(failure) = Self::reject_unimplemented(message) {
            rec.fail(SmtpStage::Connect, since, &failure);
            let trace = rec.finish(self, false);
            return (Err(failure), trace);
        }

        // `connect` failing means we never had a session at all, so `tls: false` (already the
        // constructors' default) is accurate — including for a failed implicit-TLS handshake.
        let mut session = match self.connect(rec, roots).await {
            Ok(session) => session,
            Err((rec, failure)) => {
                let trace = rec.finish(self, false);
                return (Err(failure), trace);
            }
        };

        // Everything after this point runs inside a live session, so the failure's `tls` flag is
        // stamped from that session rather than defaulted. One place, so no path can forget.
        let outcome = self
            .deliver(&mut session, message, roots)
            .await
            .map_err(|mut e| {
                e.tls = session.tls;
                e
            });
        let trace = session.rec.finish(self, session.tls);
        (outcome, trace)
    }

    /// [`send_traced_with_roots`](Self::send_traced_with_roots) discarding the trace — the shape the
    /// pre-existing tests use.
    #[cfg(test)]
    async fn send_with_roots(
        &self,
        message: &SmtpMessage,
        roots: &dyn TlsRoots,
    ) -> Result<SmtpDelivery, SmtpFailure> {
        self.send_traced_with_roots(message, roots).await.0
    }

    /// Refuse, up front and by name, the parts of SMTP this client does **not** implement.
    ///
    /// This client covers exactly: STARTTLS + implicit TLS, `AUTH PLAIN` and `AUTH LOGIN`, and an
    /// ASCII-addressed, base64 7-bit-clean single-recipient message. Everything outside that is
    /// refused with an actionable message rather than negotiated on a guess — a client that
    /// silently mis-negotiates against an unfamiliar relay is the worst thing to hand a self-hosted
    /// operator, because the person debugging it is not the person who wrote it.
    ///
    /// **SMTPUTF8 (RFC 6531) is not implemented.** An internationalized address in `MAIL FROM` /
    /// `RCPT TO` requires negotiating the `SMTPUTF8` extension; sending raw UTF-8 in the envelope
    /// without it is exactly the "works against one server, mangles against another" failure mode.
    /// So a non-ASCII envelope address is refused here instead. (Non-ASCII *display names* and
    /// *subjects* are fine — those are header content, RFC 2047 encoded by `encode_header_word`.)
    fn reject_unimplemented(message: &SmtpMessage) -> Result<(), SmtpFailure> {
        for (field, address) in [
            ("from_address", &message.from_address),
            ("to_address", &message.to_address),
        ] {
            if !address.is_ascii() {
                return Err(SmtpFailure::new(
                    SmtpStage::Connect,
                    SmtpFailureKind::Configuration,
                    format!(
                        "{field} {address:?} contains non-ASCII characters, which needs the \
                         SMTPUTF8 extension (RFC 6531); this client does not implement it, so it \
                         refuses rather than send an envelope the relay may silently mangle. Use \
                         an ASCII address — an accented display name is fine."
                    ),
                ));
            }
        }
        Ok(())
    }

    async fn deliver(
        &self,
        session: &mut Session,
        message: &SmtpMessage,
        roots: &dyn TlsRoots,
    ) -> Result<SmtpDelivery, SmtpFailure> {
        // Opening banner.
        let since = Instant::now();
        let greeting = session
            .read_reply(SmtpStage::Greeting)
            .await
            .and_then(|r| Session::expect_positive(r, SmtpStage::Greeting))
            .inspect_err(|e| session.rec.fail(SmtpStage::Greeting, since, e))?;
        session.rec.ok(SmtpStage::Greeting, since, Some(&greeting));

        let mut caps = self.ehlo(session).await?;

        if self.encryption == SmtpEncryption::StartTls {
            let since = Instant::now();
            if !caps.starttls {
                let failure = SmtpFailure::new(
                    SmtpStage::StartTls,
                    SmtpFailureKind::TlsUnsupported,
                    "the server did not advertise STARTTLS, so the connection cannot be encrypted; \
                     fix the relay, use implicit TLS on port 465, or explicitly select no \
                     encryption",
                );
                session.rec.fail(SmtpStage::StartTls, since, &failure);
                return Err(failure);
            }
            self.start_tls(session, roots).await?;
            // Capabilities before and after the upgrade are independent; only the encrypted set counts.
            caps = self.ehlo(session).await?;
        } else {
            // Recorded rather than omitted: an operator looking at an implicit-TLS or plaintext
            // session should see that STARTTLS was deliberately not part of the plan, not wonder
            // whether it was tried and quietly dropped.
            session.rec.skipped(
                SmtpStage::StartTls,
                match self.encryption {
                    SmtpEncryption::ImplicitTls => {
                        "not applicable: the session was already encrypted from the first byte \
                         (implicit TLS)"
                    }
                    _ => "not attempted: encryption is set to none for this relay",
                },
            );
        }

        let authenticated = self.authenticate(session, &caps).await?;

        // Envelope. A rejection at MAIL FROM is a sender the relay will not accept; at RCPT TO it is
        // usually relay denial. Reporting them under distinct stages is the whole point.
        let since = Instant::now();
        let mail_from = session
            .command(
                SmtpStage::MailFrom,
                &format!("MAIL FROM:<{}>", message.from_address),
            )
            .await
            .and_then(|r| Session::expect_positive(r, SmtpStage::MailFrom))
            .inspect_err(|e| session.rec.fail(SmtpStage::MailFrom, since, e))?;
        session.rec.ok(SmtpStage::MailFrom, since, Some(&mail_from));

        let since = Instant::now();
        let rcpt_to = session
            .command(
                SmtpStage::RcptTo,
                &format!("RCPT TO:<{}>", message.to_address),
            )
            .await
            .and_then(|r| Session::expect_positive(r, SmtpStage::RcptTo))
            .inspect_err(|e| session.rec.fail(SmtpStage::RcptTo, since, e))?;
        session.rec.ok(SmtpStage::RcptTo, since, Some(&rcpt_to));

        // DATA: a 354 intermediate, then the body, then the terminating dot.
        let since = Instant::now();
        let accepted = self
            .send_body(session, message)
            .await
            .inspect_err(|e| session.rec.fail(SmtpStage::Data, since, e))?;
        session.rec.ok(SmtpStage::Data, since, Some(&accepted));

        // QUIT is best-effort: the relay already accepted the message, so a failure to say goodbye
        // must not be reported as a delivery failure. It is still traced, because a relay that
        // drops the connection instead of answering QUIT is a real (if harmless) oddity.
        let since = Instant::now();
        match session.command(SmtpStage::Quit, "QUIT").await {
            Ok(reply) => session.rec.ok(SmtpStage::Quit, since, Some(&reply)),
            Err(e) => session.rec.fail(SmtpStage::Quit, since, &e),
        }

        Ok(SmtpDelivery {
            tls: session.tls,
            authenticated,
            accepted_detail: accepted.text,
        })
    }

    /// Open the TCP connection (and, in implicit-TLS mode, the handshake).
    ///
    /// Takes the [`Recorder`] by value and hands it back on either arm, because a connect failure
    /// still has a trace worth returning — the resolved address and the connect timing are exactly
    /// what distinguishes a DNS typo from a blocked port.
    async fn connect(
        &self,
        mut rec: Recorder,
        roots: &dyn TlsRoots,
    ) -> Result<Session, (Recorder, SmtpFailure)> {
        let address = format!("{}:{}", self.host, self.port);
        let since = Instant::now();
        let connected = tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect(&address))
            .await
            .map_err(|_| {
                SmtpFailure::new(
                    SmtpStage::Connect,
                    SmtpFailureKind::Timeout,
                    format!(
                        "timed out after {}s connecting to {address}",
                        STEP_TIMEOUT.as_secs()
                    ),
                )
            })
            .and_then(|r| {
                r.map_err(|e| {
                    let mut failure = SmtpFailure::from_io(SmtpStage::Connect, &e);
                    // `connect` on an unresolvable name has no dedicated stable `ErrorKind`, so it
                    // arrives as a generic error whose text names the resolver. Sniffing that text is
                    // inexact, but the alternative is telling an operator with a typo'd hostname to
                    // check their firewall.
                    let text = e.to_string().to_ascii_lowercase();
                    if text.contains("resolve")
                        || text.contains("not known")
                        || text.contains("no such host")
                        || text.contains("nodename")
                    {
                        failure.kind = SmtpFailureKind::Dns;
                    }
                    failure.detail = format!("{address}: {}", failure.detail);
                    failure
                })
            });

        let tcp = match connected {
            Ok(tcp) => tcp,
            Err(failure) => {
                rec.fail(SmtpStage::Connect, since, &failure);
                return Err((rec, failure));
            }
        };
        // Where the name actually resolved to. A hostname pointing at an unexpected address — an
        // stale /etc/hosts entry, a split-horizon DNS answer — is invisible without this.
        rec.resolved_address = tcp.peer_addr().ok().map(|a| a.to_string());
        rec.ok(SmtpStage::Connect, since, None);

        let stream = if self.encryption == SmtpEncryption::ImplicitTls {
            let since = Instant::now();
            match self.handshake(tcp, roots).await {
                Ok(tls) => {
                    rec.tls = Some(tls_detail(tls.get_ref().1));
                    rec.ok(SmtpStage::Tls, since, None);
                    SmtpStream::Tls(Box::new(tls))
                }
                Err(failure) => {
                    rec.fail(SmtpStage::Tls, since, &failure);
                    return Err((rec, failure));
                }
            }
        } else {
            SmtpStream::Plain(tcp)
        };
        let tls = self.encryption == SmtpEncryption::ImplicitTls;
        Ok(Session {
            stream: BufReader::new(stream),
            tls,
            rec,
        })
    }

    async fn handshake(
        &self,
        tcp: TcpStream,
        roots: &dyn TlsRoots,
    ) -> Result<TlsStream<TcpStream>, SmtpFailure> {
        let server_name = ServerName::try_from(self.host.clone()).map_err(|_| {
            SmtpFailure::new(
                SmtpStage::Tls,
                SmtpFailureKind::Configuration,
                format!(
                    "{:?} is not a valid TLS server name; TLS needs a hostname, not a bare address \
                     form it cannot verify",
                    self.host
                ),
            )
        })?;
        let connector = TlsConnector::from(roots.client_config()?);
        tokio::time::timeout(STEP_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .map_err(|_| {
                SmtpFailure::new(
                    SmtpStage::Tls,
                    SmtpFailureKind::Timeout,
                    format!(
                        "timed out after {}s during the TLS handshake",
                        STEP_TIMEOUT.as_secs()
                    ),
                )
            })?
            // rustls renders the real reason here — `UnknownIssuer`, `NotValidForName`,
            // `CertExpired`, `HandshakeFailure` — so it is passed through untouched.
            .map_err(|e| SmtpFailure::new(SmtpStage::Tls, SmtpFailureKind::Tls, e.to_string()))
    }

    async fn ehlo(&self, session: &mut Session) -> Result<Capabilities, SmtpFailure> {
        let since = Instant::now();
        let reply = session
            .command(SmtpStage::Ehlo, &format!("EHLO {}", self.helo_name))
            .await
            .and_then(|r| Session::expect_positive(r, SmtpStage::Ehlo))
            .inspect_err(|e| session.rec.fail(SmtpStage::Ehlo, since, e))?;
        session.rec.ok(SmtpStage::Ehlo, since, Some(&reply));
        // The advertised extension list, verbatim. "The relay never offered AUTH" and "the relay
        // offered only CRAM-MD5" are different problems with the same symptom, and this is the only
        // place the difference is visible. Overwritten by the post-STARTTLS EHLO, which is the set
        // that actually governed the session.
        session.rec.advertised_capabilities = reply.lines.iter().skip(1).cloned().collect();
        Ok(Capabilities::parse(&reply.lines))
    }

    /// `DATA`, the body, and the terminating dot — split out so the whole exchange is one traced
    /// stage with one duration, which is what an operator debugging a size or content rejection
    /// wants to see.
    async fn send_body(
        &self,
        session: &mut Session,
        message: &SmtpMessage,
    ) -> Result<SmtpReply, SmtpFailure> {
        let data = session.command(SmtpStage::Data, "DATA").await?;
        if data.code != 354 {
            return Err(SmtpFailure::from_reply(SmtpStage::Data, &data));
        }
        let body = render_message(message);
        // The body is bulk content, not conversation: a summary line keeps the transcript readable
        // and keeps the recipient's message text out of a payload an operator may paste into a
        // support ticket.
        let summary = format!("<message body: {} bytes>", body.len());
        session.rec.line(SmtpTranscriptDirection::Client, &summary);
        session.write_line(SmtpStage::Data, &body).await?;
        let accepted = session.command(SmtpStage::Data, ".").await?;
        Session::expect_positive(accepted, SmtpStage::Data)
    }

    async fn start_tls(
        &self,
        session: &mut Session,
        roots: &dyn TlsRoots,
    ) -> Result<(), SmtpFailure> {
        let since = Instant::now();
        let reply = session
            .command(SmtpStage::StartTls, "STARTTLS")
            .await
            .and_then(|r| Session::expect_positive(r, SmtpStage::StartTls));
        let reply = match reply {
            Ok(reply) => reply,
            Err(e) => {
                session.rec.fail(SmtpStage::StartTls, since, &e);
                return Err(e);
            }
        };

        // STARTTLS response injection (CVE-2011-0411): anything already buffered was sent before the
        // handshake and must not be trusted as part of the encrypted session.
        if !session.stream.buffer().is_empty() {
            let failure = SmtpFailure::new(
                SmtpStage::StartTls,
                SmtpFailureKind::Protocol,
                "the server pipelined data after its STARTTLS reply; refusing the upgrade because \
                 that plaintext could be injected into the encrypted session",
            );
            session.rec.fail(SmtpStage::StartTls, since, &failure);
            return Err(failure);
        }

        let SmtpStream::Plain(tcp) =
            std::mem::replace(session.stream.get_mut(), SmtpStream::Upgrading)
        else {
            let failure = SmtpFailure::new(
                SmtpStage::StartTls,
                SmtpFailureKind::Protocol,
                "the connection was already encrypted when STARTTLS was attempted",
            );
            session.rec.fail(SmtpStage::StartTls, since, &failure);
            return Err(failure);
        };
        session.rec.ok(SmtpStage::StartTls, since, Some(&reply));

        // On handshake failure the session is dropped by the caller, so the `Upgrading` placeholder
        // is never read from.
        let since = Instant::now();
        let tls = match self.handshake(tcp, roots).await {
            Ok(tls) => tls,
            Err(e) => {
                session.rec.fail(SmtpStage::Tls, since, &e);
                return Err(e);
            }
        };
        session.rec.tls = Some(tls_detail(tls.get_ref().1));
        session.rec.ok(SmtpStage::Tls, since, None);
        *session.stream.get_mut() = SmtpStream::Tls(Box::new(tls));
        session.tls = true;
        Ok(())
    }

    /// Authenticate if a username is configured. Returns whether AUTH ran.
    async fn authenticate(
        &self,
        session: &mut Session,
        caps: &Capabilities,
    ) -> Result<bool, SmtpFailure> {
        let (Some(username), Some(password)) = (&self.username, &self.password) else {
            session
                .rec
                .skipped(SmtpStage::Auth, "no relay username is configured");
            return Ok(false);
        };
        if username.is_empty() {
            session
                .rec
                .skipped(SmtpStage::Auth, "no relay username is configured");
            return Ok(false);
        }
        let since = Instant::now();
        if !caps.auth_plain && !caps.auth_login {
            let failure = SmtpFailure::new(
                SmtpStage::Auth,
                SmtpFailureKind::Configuration,
                "a username is configured but the server advertised no AUTH mechanism this client \
                 supports (PLAIN or LOGIN); if the relay needs no credentials, clear the username",
            );
            session.rec.fail(SmtpStage::Auth, since, &failure);
            return Err(failure);
        }

        // Which mechanism was chosen is recorded; what was sent with it is not.
        session.rec.auth_mechanism =
            Some(if caps.auth_plain { "PLAIN" } else { "LOGIN" }.to_owned());

        let reply = if caps.auth_plain {
            // RFC 4616: authzid NUL authcid NUL passwd, base64. Zeroized after encoding.
            let mut raw = Zeroizing::new(Vec::new());
            raw.push(0);
            raw.extend_from_slice(username.as_bytes());
            raw.push(0);
            raw.extend_from_slice(password.as_bytes());
            let encoded = Zeroizing::new(BASE64.encode(&*raw));
            session
                .command_redacted(
                    SmtpStage::Auth,
                    &format!("AUTH PLAIN {}", *encoded),
                    "AUTH PLAIN <redacted>",
                )
                .await
                .inspect_err(|e| session.rec.fail(SmtpStage::Auth, since, e))?
        } else {
            let start = session
                .command(SmtpStage::Auth, "AUTH LOGIN")
                .await
                .inspect_err(|e| session.rec.fail(SmtpStage::Auth, since, e))?;
            if start.code != 334 {
                let failure = SmtpFailure::from_reply(SmtpStage::Auth, &start);
                session.rec.fail(SmtpStage::Auth, since, &failure);
                return Err(failure);
            }
            // The username is not a secret, but it is still shown redacted: the challenge responses
            // of AUTH LOGIN are positional, and a transcript showing one base64 blob and hiding the
            // next invites the reader to decode the one that is there.
            let user_reply = session
                .command_redacted(
                    SmtpStage::Auth,
                    &BASE64.encode(username.as_bytes()),
                    "<username, base64>",
                )
                .await
                .inspect_err(|e| session.rec.fail(SmtpStage::Auth, since, e))?;
            if user_reply.code != 334 {
                let failure = SmtpFailure::from_reply(SmtpStage::Auth, &user_reply);
                session.rec.fail(SmtpStage::Auth, since, &failure);
                return Err(failure);
            }
            let encoded = Zeroizing::new(BASE64.encode(password.as_bytes()));
            session
                .command_redacted(SmtpStage::Auth, &encoded, "<redacted>")
                .await
                .inspect_err(|e| session.rec.fail(SmtpStage::Auth, since, e))?
        };

        // A 535 here is the single most common real-world mail misconfiguration. The server's own
        // text ("authentication failed", "Username and Password not accepted", …) is what the
        // operator needs, so it is reported verbatim.
        let reply = Session::expect_positive(reply, SmtpStage::Auth)
            .inspect_err(|e| session.rec.fail(SmtpStage::Auth, since, e))?;
        session.rec.ok(SmtpStage::Auth, since, Some(&reply));
        Ok(true)
    }
}

/// Where the client's TLS trust anchors come from.
///
/// The one seam that makes the encrypted half of this module observable. It supplies **only the set
/// of trusted roots**: certificate verification, hostname/IP matching, protocol versions and the
/// crypto provider are all still rustls's, identically on every path. There is therefore no
/// implementation of this trait — present or future — that can skip the handshake, accept an
/// untrusted certificate, or send `AUTH` any earlier than the real one does.
///
/// The trait, its production implementation and the only function taking it are all private to this
/// module, and [`SmtpClient::send`] — the sole entry point the rest of the crate has — hard-codes
/// [`NativeRoots`]. Nothing in a release build can select anything else, and no configuration key
/// reaches it.
trait TlsRoots: Send + Sync {
    fn client_config(&self) -> Result<Arc<ClientConfig>, SmtpFailure>;
}

/// The production trust source: the operating system's root store.
struct NativeRoots;

impl TlsRoots for NativeRoots {
    fn client_config(&self) -> Result<Arc<ClientConfig>, SmtpFailure> {
        tls_config()
    }
}

/// Read what the completed handshake negotiated, for the diagnostic trace.
///
/// Everything here is already-verified public information: the protocol version, the cipher suite,
/// and the two distinguished names on the leaf certificate the relay presented. No private material
/// and nothing about this client's own configuration passes through.
///
/// The DN rendering follows the same idiom as the rest of the crate's certificate handling
/// (`x509_cert::Certificate::from_der(…).tbs_certificate.subject`), so a name is formatted the same
/// way here as in signature validation. `x509-cert` is already a direct dependency, so this costs
/// no new crate.
fn tls_detail(conn: &tokio_rustls::rustls::CommonState) -> SmtpTlsDetail {
    use x509_cert::der::Decode as _;

    let leaf = conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .and_then(|der| x509_cert::Certificate::from_der(der.as_ref()).ok());

    SmtpTlsDetail {
        protocol: conn.protocol_version().map(|v| format!("{v:?}")),
        cipher_suite: conn
            .negotiated_cipher_suite()
            .and_then(|s| s.suite().as_str().map(str::to_owned)),
        peer_subject: leaf.as_ref().map(|c| c.tbs_certificate.subject.to_string()),
        peer_issuer: leaf.as_ref().map(|c| c.tbs_certificate.issuer.to_string()),
    }
}

/// Build the rustls client config: OS trust store, safe defaults.
///
/// The provider is named explicitly (`ring`) rather than taken from the process default, because
/// this workspace links both `ring` and `aws-lc-rs` through other dependencies and
/// `CryptoProvider::get_default()` panics when neither has been installed.
fn tls_config() -> Result<Arc<ClientConfig>, SmtpFailure> {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for cert in loaded.certs {
        // A single unparseable OS certificate must not take down the whole trust store.
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(SmtpFailure::new(
            SmtpStage::Tls,
            SmtpFailureKind::Configuration,
            "no trusted root certificates could be loaded from the operating system, so the \
             relay's certificate cannot be verified",
        ));
    }
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| SmtpFailure::new(SmtpStage::Tls, SmtpFailureKind::Tls, e.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

// --- Message rendering -------------------------------------------------------------------------

/// Render the RFC 5322 message. The body is base64 so arbitrary UTF-8 survives relays that are not
/// 8BITMIME-clean and no line can exceed the 998-octet limit; headers are RFC 2047 encoded when they
/// are not pure ASCII.
fn render_message(message: &SmtpMessage) -> String {
    let from = match &message.from_name {
        Some(name) if !name.trim().is_empty() => {
            format!("{} <{}>", encode_header_word(name), message.from_address)
        }
        _ => message.from_address.clone(),
    };
    let mut out = String::new();
    out.push_str(&format!("From: {from}\r\n"));
    out.push_str(&format!("To: {}\r\n", message.to_address));
    out.push_str(&format!(
        "Subject: {}\r\n",
        encode_header_word(&message.subject)
    ));
    out.push_str(&format!("Date: {}\r\n", message.date));
    out.push_str(&format!("Message-ID: <{}>\r\n", message.message_id));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Auto-Submitted: auto-generated\r\n");

    match &message.html_body {
        None => {
            out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            out.push_str("Content-Transfer-Encoding: base64\r\n");
            out.push_str("\r\n");
            push_base64_body(&mut out, &message.body);
        }
        Some(html) => {
            // A boundary that cannot occur inside either part: both parts are base64, whose alphabet
            // excludes '=' except as terminal padding and excludes '_' entirely, so no generated
            // line can collide with it. Derived from the Message-ID rather than random so the same
            // message renders byte-identically twice — which is what makes the structure testable.
            let boundary = multipart_boundary(&message.message_id);
            out.push_str(&format!(
                "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n"
            ));
            out.push_str("\r\n");
            // Read by nothing that matters, but a client too old to understand multipart shows it
            // instead of nothing at all.
            out.push_str("This is a message in MIME multipart/alternative format.\r\n");

            // Part 1 — text/plain. First, per RFC 2046 §5.1.4: a client picks the *last* part it
            // understands, so the plain-text part must precede the HTML one.
            out.push_str(&format!("\r\n--{boundary}\r\n"));
            out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            out.push_str("Content-Transfer-Encoding: base64\r\n");
            out.push_str("\r\n");
            push_base64_body(&mut out, &message.body);

            // Part 2 — text/html.
            out.push_str(&format!("\r\n--{boundary}\r\n"));
            out.push_str("Content-Type: text/html; charset=utf-8\r\n");
            out.push_str("Content-Transfer-Encoding: base64\r\n");
            out.push_str("\r\n");
            push_base64_body(&mut out, html);

            out.push_str(&format!("\r\n--{boundary}--\r\n"));
        }
    }

    // Base64 output can never begin a line with '.', and neither can a boundary line ("--…"), so no
    // dot-stuffing pass is needed; the terminating "." is written by the caller as its own command.
    out.trim_end_matches("\r\n").to_owned()
}

/// Append a body as base64, wrapped at 76 columns so no line approaches the 998-octet limit.
fn push_base64_body(out: &mut String, body: &str) {
    let encoded = BASE64.encode(body.as_bytes());
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str("\r\n");
    }
}

/// A MIME boundary derived from the Message-ID, restricted to characters that cannot appear in
/// base64 output so it can never collide with a body line.
fn multipart_boundary(message_id: &str) -> String {
    let tail: String = message_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(32)
        .collect();
    format!("=_chancela_{tail}_=")
}

/// RFC 2047 `=?UTF-8?B?…?=` encoding, applied only when the value is not plain printable ASCII.
fn encode_header_word(value: &str) -> String {
    let plain = value
        .bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b'?' && b != b'=');
    if plain {
        return value.to_owned();
    }
    format!("=?UTF-8?B?{}?=", BASE64.encode(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    // --- A scriptable loopback relay -----------------------------------------------------------
    //
    // `smtp_settings.rs` already drives the *handler* against a fixed fake relay. These tests are
    // about the wire protocol itself, so the relay here is scriptable and — the part that carries
    // the security assertions — **records what the client actually sent**. "The call returned an
    // error" is a much weaker claim than "the password never reached the socket"; only a transcript
    // can make the second one.

    /// What the relay does about transport security.
    enum RelayTls {
        /// Cleartext only — the relay cannot complete a handshake at all.
        None,
        /// Cleartext, then a **real** rustls handshake once the client sends `STARTTLS`.
        StartTls(TlsAcceptor),
        /// Real TLS from the first byte (SMTPS).
        Implicit(TlsAcceptor),
    }

    /// One line the client sent, tagged with whether it travelled inside TLS.
    ///
    /// This tag is the whole point of the harness: "the send succeeded" says nothing about *when*
    /// the password crossed the wire. A transcript split by encryption state can state it directly.
    #[derive(Clone)]
    struct RelayLine {
        encrypted: bool,
        text: String,
    }

    /// A one-connection fake relay. `reply` is called with each command line the client sends and
    /// returns the raw bytes to write back (returning `None` closes the connection); it may hold its
    /// own state, which is how the multi-step `AUTH LOGIN` exchange is scripted.
    struct FakeRelay {
        port: u16,
        transcript: Arc<Mutex<Vec<RelayLine>>>,
        connections: Arc<AtomicUsize>,
    }

    /// How one leg of the conversation ended.
    enum Leg {
        /// The connection finished (or the script closed it).
        Finished,
        /// The client asked for `STARTTLS` and the relay agreed: hand the socket to the acceptor.
        Upgrade,
    }

    /// Run the SMTP conversation over one stream, recording every client line against `encrypted`.
    async fn converse<S, F>(
        stream: &mut BufReader<S>,
        encrypted: bool,
        upgradable: bool,
        reply: &mut F,
        recorded: &Arc<Mutex<Vec<RelayLine>>>,
    ) -> Leg
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        F: FnMut(&str) -> Option<String> + Send,
    {
        // `DATA` hands the connection to the message body, which is many lines answered by a
        // single reply. That is protocol structure rather than script, so the loop owns it —
        // a relay that answered every body line would desynchronise the exchange.
        let mut in_data = false;
        loop {
            let mut line = String::new();
            match stream.read_line(&mut line).await {
                Ok(0) | Err(_) => return Leg::Finished,
                Ok(_) => {}
            }
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            recorded.lock().expect("transcript").push(RelayLine {
                encrypted,
                text: line.clone(),
            });
            if in_data {
                if line != "." {
                    continue;
                }
                in_data = false;
            } else if line.to_ascii_uppercase().starts_with("DATA") {
                in_data = true;
            }
            let Some(answer) = reply(&line) else {
                return Leg::Finished;
            };
            if stream.get_mut().write_all(answer.as_bytes()).await.is_err() {
                return Leg::Finished;
            }
            if upgradable && line.eq_ignore_ascii_case("STARTTLS") && answer.starts_with("220") {
                return Leg::Upgrade;
            }
        }
    }

    impl FakeRelay {
        /// A cleartext relay.
        async fn spawn<F>(reply: F) -> Self
        where
            F: FnMut(&str) -> Option<String> + Send + 'static,
        {
            Self::spawn_with(RelayTls::None, reply).await
        }

        async fn spawn_with<F>(tls: RelayTls, mut reply: F) -> Self
        where
            F: FnMut(&str) -> Option<String> + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let transcript = Arc::new(Mutex::new(Vec::new()));
            let connections = Arc::new(AtomicUsize::new(0));
            let recorded = Arc::clone(&transcript);
            let counted = Arc::clone(&connections);
            let (acceptor, implicit) = match tls {
                RelayTls::None => (None, false),
                RelayTls::StartTls(acceptor) => (Some(acceptor), false),
                RelayTls::Implicit(acceptor) => (Some(acceptor), true),
            };
            tokio::spawn(async move {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                const GREETING: &[u8] = b"220 relay.example.pt ESMTP ready\r\n";

                if implicit {
                    let acceptor = acceptor.expect("implicit TLS needs an acceptor");
                    let Ok(stream) = acceptor.accept(socket).await else {
                        return;
                    };
                    let mut buffered = BufReader::new(stream);
                    if buffered.get_mut().write_all(GREETING).await.is_err() {
                        return;
                    }
                    converse(&mut buffered, true, false, &mut reply, &recorded).await;
                    return;
                }

                let mut buffered = BufReader::new(socket);
                if buffered.get_mut().write_all(GREETING).await.is_err() {
                    return;
                }
                let upgradable = acceptor.is_some();
                if let Leg::Upgrade =
                    converse(&mut buffered, false, upgradable, &mut reply, &recorded).await
                {
                    let acceptor = acceptor.expect("an upgrade only happens with an acceptor");
                    // Nothing may be left buffered here: the client refuses the upgrade if the
                    // relay pipelined anything, so `into_inner` cannot be discarding client bytes.
                    let Ok(stream) = acceptor.accept(buffered.into_inner()).await else {
                        return;
                    };
                    let mut buffered = BufReader::new(stream);
                    converse(&mut buffered, true, false, &mut reply, &recorded).await;
                }
            });
            Self {
                port,
                transcript,
                connections,
            }
        }

        fn lines(&self) -> Vec<RelayLine> {
            self.transcript.lock().expect("transcript").clone()
        }

        fn transcript(&self) -> Vec<String> {
            self.lines().into_iter().map(|l| l.text).collect()
        }

        /// Every line the client sent, joined — for `contains` assertions over the whole exchange.
        fn wire(&self) -> String {
            self.transcript().join("\n")
        }

        /// Only what the client sent **before** the session was encrypted. A passive eavesdropper on
        /// the TCP connection sees exactly this and nothing else.
        fn cleartext_wire(&self) -> String {
            self.joined(false)
        }

        /// Only what the client sent **inside** TLS.
        fn encrypted_wire(&self) -> String {
            self.joined(true)
        }

        fn joined(&self, encrypted: bool) -> String {
            self.lines()
                .into_iter()
                .filter(|l| l.encrypted == encrypted)
                .map(|l| l.text)
                .collect::<Vec<_>>()
                .join("\n")
        }

        fn connections(&self) -> usize {
            self.connections.load(Ordering::SeqCst)
        }
    }

    // --- A throwaway PKI, so the handshake under test is a real one ------------------------------
    //
    // The relay needs a certificate the client will actually accept, and the client must reach it
    // through the ordinary rustls verifier — otherwise "the handshake completed" would only mean
    // "verification was skipped". So: a self-signed test CA, a loopback server certificate it
    // issues (`serverAuth` EKU, `IP:127.0.0.1` SAN), and a `TlsRoots` implementation that trusts
    // that CA and nothing else. Versions, provider and name checking are all production behaviour.

    /// DER bytes for the test CA and the server certificate it signs, plus the server's PKCS#8 key.
    struct TestPki {
        ca_cert: Vec<u8>,
        server_cert: Vec<u8>,
        server_key: Vec<u8>,
    }

    /// Fixed key material: these are test fixtures, so they are deterministic rather than random.
    const CA_KEY_BYTES: [u8; 32] = [0x11; 32];
    const SERVER_KEY_BYTES: [u8; 32] = [0x22; 32];

    fn test_pki() -> &'static TestPki {
        use std::str::FromStr;
        use std::sync::OnceLock;

        use der::Encode;
        use der::asn1::{Any, BitString, OctetString};
        use der::oid::ObjectIdentifier;
        use p256::ecdsa::signature::Signer;
        use p256::pkcs8::EncodePrivateKey;
        use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
        use x509_cert::certificate::{Certificate, TbsCertificate, Version};
        use x509_cert::ext::Extension;
        use x509_cert::ext::pkix::name::GeneralName;
        use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, SubjectAltName};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        const ID_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
        const ID_CE_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
        const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
        const ID_KP_SERVER_AUTH: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
        const ECDSA_WITH_SHA256: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

        fn extension(oid: ObjectIdentifier, critical: bool, value: Vec<u8>) -> Extension {
            Extension {
                extn_id: oid,
                critical,
                extn_value: OctetString::new(value).expect("extension value"),
            }
        }

        /// Build one certificate and sign it with `issuer_key`.
        fn issue(
            cn: &str,
            serial: u8,
            subject_key: &p256::ecdsa::SigningKey,
            issuer_cn: &str,
            issuer_key: &p256::ecdsa::SigningKey,
            extensions: Vec<Extension>,
        ) -> Vec<u8> {
            let sig_alg = AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None::<Any>,
            };
            let spki =
                SubjectPublicKeyInfoOwned::from_key(*subject_key.verifying_key()).expect("spki");
            let tbs = TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[serial]).expect("serial"),
                signature: sig_alg.clone(),
                issuer: Name::from_str(&format!("CN={issuer_cn}")).expect("issuer"),
                validity: Validity::from_now(std::time::Duration::from_secs(365 * 24 * 3600))
                    .expect("validity"),
                subject: Name::from_str(&format!("CN={cn}")).expect("subject"),
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(extensions),
            };
            let tbs_der = tbs.to_der().expect("tbs der");
            let signature: p256::ecdsa::Signature = issuer_key.sign(&tbs_der);
            Certificate {
                tbs_certificate: tbs,
                signature_algorithm: sig_alg,
                signature: BitString::from_bytes(signature.to_der().as_bytes())
                    .expect("signature bitstring"),
            }
            .to_der()
            .expect("certificate der")
        }

        static PKI: OnceLock<TestPki> = OnceLock::new();
        PKI.get_or_init(|| {
            let ca_key =
                p256::ecdsa::SigningKey::from_slice(&CA_KEY_BYTES).expect("valid CA scalar");
            let server_signing_key = p256::ecdsa::SigningKey::from_slice(&SERVER_KEY_BYTES)
                .expect("valid server scalar");

            let ca_cert = issue(
                "Chancela Test Relay CA",
                1,
                &ca_key,
                "Chancela Test Relay CA",
                &ca_key,
                vec![extension(
                    ID_CE_BASIC_CONSTRAINTS,
                    true,
                    BasicConstraints {
                        ca: true,
                        path_len_constraint: Some(0),
                    }
                    .to_der()
                    .expect("basic constraints"),
                )],
            );
            let server_cert = issue(
                "relay.example.pt",
                2,
                &server_signing_key,
                "Chancela Test Relay CA",
                &ca_key,
                vec![
                    extension(
                        ID_CE_BASIC_CONSTRAINTS,
                        true,
                        BasicConstraints {
                            ca: false,
                            path_len_constraint: None,
                        }
                        .to_der()
                        .expect("basic constraints"),
                    ),
                    extension(
                        ID_CE_EXT_KEY_USAGE,
                        false,
                        ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH])
                            .to_der()
                            .expect("eku"),
                    ),
                    // The client dials 127.0.0.1, so the name rustls verifies is an IP address.
                    extension(
                        ID_CE_SUBJECT_ALT_NAME,
                        false,
                        SubjectAltName(vec![GeneralName::IpAddress(
                            OctetString::new(vec![127, 0, 0, 1]).expect("ip san"),
                        )])
                        .to_der()
                        .expect("san"),
                    ),
                ],
            );
            let server_key = p256::SecretKey::from_slice(&SERVER_KEY_BYTES)
                .expect("valid server scalar")
                .to_pkcs8_der()
                .expect("pkcs8")
                .as_bytes()
                .to_vec();
            TestPki {
                ca_cert,
                server_cert,
                server_key,
            }
        })
    }

    /// A rustls acceptor presenting the test server certificate.
    fn test_acceptor() -> TlsAcceptor {
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let pki = test_pki();
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(pki.server_cert.clone()),
                CertificateDer::from(pki.ca_cert.clone()),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_key.clone())),
        )
        .expect("server certificate");
        TlsAcceptor::from(Arc::new(config))
    }

    /// The test trust source: the throwaway CA, and nothing else. Everything the real
    /// [`NativeRoots`] does — certificate verification, name checking, protocol versions, crypto
    /// provider — is untouched; only the anchor set differs, which is why a handshake that
    /// completes here is a real one.
    struct TestRoots;

    impl TlsRoots for TestRoots {
        fn client_config(&self) -> Result<Arc<ClientConfig>, SmtpFailure> {
            let mut roots = RootCertStore::empty();
            roots
                .add(tokio_rustls::rustls::pki_types::CertificateDer::from(
                    test_pki().ca_cert.clone(),
                ))
                .expect("the test CA parses");
            let config = ClientConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Ok(Arc::new(config))
        }
    }

    /// The stock EHLO answer: STARTTLS offered, `AUTH PLAIN LOGIN` offered.
    const EHLO_FULL: &str =
        "250-relay.example.pt\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n";

    fn client(port: u16, encryption: SmtpEncryption, credentials: bool) -> SmtpClient {
        SmtpClient {
            host: "127.0.0.1".to_owned(),
            port,
            encryption,
            username: credentials.then(|| "sistema".to_owned()),
            password: credentials.then(|| Zeroizing::new("Palavra-Passe-Do-Relay-9!".to_owned())),
            helo_name: "encosto-estrategico.pt".to_owned(),
        }
    }

    fn message() -> SmtpMessage {
        SmtpMessage {
            from_address: "sistema@encosto-estrategico.pt".to_owned(),
            from_name: Some("Encosto Estratégico Lda".to_owned()),
            to_address: "amelia.marques@encosto-estrategico.pt".to_owned(),
            subject: "Teste de configuração".to_owned(),
            body: "Olá — configuração validada.".to_owned(),
            html_body: None,
            date: "Mon, 20 Jul 2026 09:00:00 +0100".to_owned(),
            message_id: "abc@encosto-estrategico.pt".to_owned(),
        }
    }

    /// The same message with both parts, for the `multipart/alternative` tests.
    fn multipart_message() -> SmtpMessage {
        SmtpMessage {
            html_body: Some(
                "<p style=\"color:#10241b\">Olá — configuração validada.</p>".to_owned(),
            ),
            ..message()
        }
    }

    /// Nothing that would let an eavesdropper impersonate the account, or learn who is being
    /// written to, may appear on a connection that never became encrypted.
    fn assert_nothing_sensitive_on_the_wire(relay: &FakeRelay) {
        let wire = relay.wire().to_ascii_uppercase();
        for forbidden in ["AUTH", "MAIL FROM", "RCPT TO", "DATA"] {
            assert!(
                !wire.contains(forbidden),
                "{forbidden} was sent over an unencrypted connection: {}",
                relay.wire()
            );
        }
    }

    /// A relay that completes the whole exchange happily: the script every TLS test below reuses,
    /// so what differs between them is the transport, not the conversation.
    fn accepting_reply(line: &str) -> Option<String> {
        let upper = line.to_ascii_uppercase();
        Some(if upper.starts_with("EHLO") {
            EHLO_FULL.to_owned()
        } else if upper.starts_with("STARTTLS") {
            "220 Ready to start TLS\r\n".to_owned()
        } else if upper.starts_with("AUTH") || upper.starts_with("MAIL FROM") {
            "235 2.7.0 Authentication successful\r\n".to_owned()
        } else if upper.starts_with("DATA") {
            "354 End data with <CR><LF>.<CR><LF>\r\n".to_owned()
        } else if line == "." {
            "250 2.0.0 Ok: queued as 8F2A1\r\n".to_owned()
        } else if upper.starts_with("QUIT") {
            "221 Bye\r\n".to_owned()
        } else {
            "250 Ok\r\n".to_owned()
        })
    }

    /// Nothing that authenticates the account or names the correspondents may appear in the
    /// **cleartext** part of a session that later became encrypted. This is the assertion the whole
    /// TLS harness exists to make; it reads the pre-handshake transcript, not the return value.
    fn assert_cleartext_leg_carries_only_the_handshake(relay: &FakeRelay) {
        let cleartext = relay.cleartext_wire();
        let upper = cleartext.to_ascii_uppercase();
        for forbidden in ["AUTH", "MAIL FROM", "RCPT TO", "DATA"] {
            assert!(
                !upper.contains(forbidden),
                "{forbidden} was sent before the TLS handshake: {cleartext}"
            );
        }
        assert!(
            !cleartext.contains("Palavra-Passe-Do-Relay-9!")
                && !cleartext.contains(&BASE64.encode("Palavra-Passe-Do-Relay-9!")),
            "the password appeared in the clear: {cleartext}"
        );
        assert!(
            !cleartext.contains("amelia.marques"),
            "the recipient appeared in the clear: {cleartext}"
        );
    }

    // --- Inside TLS ------------------------------------------------------------------------------
    //
    // These drive the client against a relay that completes a **real** rustls handshake, so the
    // encrypted half of the session is finally observable. Only the trust anchors are swapped (see
    // `TestRoots`); the client code path is byte-for-byte the production one.

    /// The property the whole module is built around: `AUTH` must not be sent until the STARTTLS
    /// handshake has completed. Asserted from the relay's own transcript — the credentials appear
    /// only among the lines the relay read *inside* TLS, and the cleartext leg holds nothing but
    /// `EHLO` and `STARTTLS`.
    #[tokio::test]
    async fn auth_is_not_sent_until_the_starttls_handshake_has_completed() {
        let relay =
            FakeRelay::spawn_with(RelayTls::StartTls(test_acceptor()), accepting_reply).await;

        let delivery = client(relay.port, SmtpEncryption::StartTls, true)
            .send_with_roots(&message(), &TestRoots)
            .await
            .expect("the relay completes a real handshake and accepts the message");

        assert!(delivery.tls, "the session ran inside TLS: {delivery:?}");
        assert!(delivery.authenticated);
        assert_eq!(delivery.accepted_detail, "Ok: queued as 8F2A1");

        // Before the handshake: the upgrade negotiation, and nothing else.
        assert_cleartext_leg_carries_only_the_handshake(&relay);
        let cleartext = relay.cleartext_wire();
        assert!(
            cleartext.to_ascii_uppercase().contains("EHLO")
                && cleartext.to_ascii_uppercase().contains("STARTTLS"),
            "the cleartext leg is the upgrade negotiation: {cleartext}"
        );

        // After it: the credentials, carrying the real RFC 4616 triple, decoded from what the relay
        // received on the encrypted side.
        let auth = relay
            .lines()
            .into_iter()
            .find(|l| l.text.to_ascii_uppercase().starts_with("AUTH "))
            .expect("an AUTH command was sent");
        assert!(auth.encrypted, "AUTH travelled in the clear");
        let encoded = auth
            .text
            .split_whitespace()
            .nth(2)
            .expect("the base64 argument");
        assert_eq!(
            BASE64.decode(encoded).expect("base64"),
            b"\0sistema\0Palavra-Passe-Do-Relay-9!",
            "the credentials that reached the relay are the configured ones"
        );
        // The envelope is inside TLS too — who is writing to whom is not public either.
        let encrypted = relay.encrypted_wire();
        assert!(
            encrypted.contains("RCPT TO:<amelia.marques@encosto-estrategico.pt>"),
            "the envelope must travel encrypted: {encrypted}"
        );
    }

    /// Implicit TLS (port 465) has no cleartext leg at all: the handshake happens before the
    /// greeting, so *every* line — `EHLO` included — is inside TLS.
    #[tokio::test]
    async fn implicit_tls_leaves_no_cleartext_leg_at_all() {
        let relay =
            FakeRelay::spawn_with(RelayTls::Implicit(test_acceptor()), accepting_reply).await;

        let delivery = client(relay.port, SmtpEncryption::ImplicitTls, true)
            .send_with_roots(&message(), &TestRoots)
            .await
            .expect("the relay completes a real handshake and accepts the message");

        assert!(delivery.tls);
        assert!(delivery.authenticated);
        assert_eq!(
            relay.cleartext_wire(),
            "",
            "implicit TLS must put the very first byte inside the handshake"
        );
        assert!(
            relay
                .encrypted_wire()
                .to_ascii_uppercase()
                .contains("AUTH ")
        );
        assert_cleartext_leg_carries_only_the_handshake(&relay);
    }

    /// The downgrade refusal, now against a relay that **could** have completed a handshake and
    /// simply does not advertise `STARTTLS` — the shape of a stripping MITM. The client must refuse
    /// rather than fall back, and must not have sent anything in the clear when it does.
    #[tokio::test]
    async fn a_tls_capable_relay_that_hides_starttls_is_refused_rather_than_downgraded() {
        let relay = FakeRelay::spawn_with(RelayTls::StartTls(test_acceptor()), |line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                // The relay speaks TLS perfectly well; the advertisement has been stripped.
                "250-relay.example.pt\r\n250 AUTH PLAIN LOGIN\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let failure = client(relay.port, SmtpEncryption::StartTls, true)
            .send_with_roots(&message(), &TestRoots)
            .await
            .expect_err("a stripped STARTTLS advertisement must not be answered with a downgrade");

        assert_eq!(failure.stage, SmtpStage::StartTls);
        assert_eq!(failure.kind, SmtpFailureKind::TlsUnsupported);
        assert!(!failure.tls);
        assert_eq!(
            relay.encrypted_wire(),
            "",
            "no handshake may happen after the refusal"
        );
        assert_cleartext_leg_carries_only_the_handshake(&relay);
    }

    /// CVE-2011-0411 against a relay whose handshake **would** have succeeded. The earlier cleartext
    /// version of this test could not distinguish "refused the injection" from "could not do TLS
    /// anyway"; here the upgrade is genuinely available and is still refused, and no credential
    /// follows.
    #[tokio::test]
    async fn pipelined_plaintext_aborts_an_upgrade_that_would_otherwise_have_succeeded() {
        let relay = FakeRelay::spawn_with(RelayTls::StartTls(test_acceptor()), |line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                EHLO_FULL.to_owned()
            } else if upper.starts_with("STARTTLS") {
                // One write, so both lines arrive in the same segment and the second is buffered.
                "220 Ready to start TLS\r\n250 Injected-by-a-mitm\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let failure = client(relay.port, SmtpEncryption::StartTls, true)
            .send_with_roots(&message(), &TestRoots)
            .await
            .expect_err("injected plaintext must abort the upgrade");

        assert_eq!(failure.stage, SmtpStage::StartTls);
        assert_eq!(failure.kind, SmtpFailureKind::Protocol);
        assert!(
            failure.detail.contains("pipelined"),
            "the refusal must say what it saw: {}",
            failure.detail
        );
        assert_eq!(
            relay.encrypted_wire(),
            "",
            "the client must not proceed into the handshake it just refused"
        );
        assert_cleartext_leg_carries_only_the_handshake(&relay);
    }

    // --- STARTTLS ------------------------------------------------------------------------------

    /// The advertised upgrade is actually taken: the client sends `STARTTLS` and moves on to the
    /// handshake. The relay speaks no TLS, so the handshake fails — and *that* is the observable
    /// difference from the downgrade case below, which never reaches the handshake at all.
    #[tokio::test]
    async fn starttls_is_negotiated_before_anything_else_is_sent() {
        let relay = FakeRelay::spawn(|line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                EHLO_FULL.to_owned()
            } else if upper.starts_with("STARTTLS") {
                "220 Ready to start TLS\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let failure = client(relay.port, SmtpEncryption::StartTls, true)
            .send(&message())
            .await
            .expect_err("the relay cannot complete a real handshake");

        assert_eq!(
            failure.stage,
            SmtpStage::Tls,
            "the client got past STARTTLS into the handshake: {failure:?}"
        );
        // Which handshake error surfaces depends on the host's trust store, so the assertion is on
        // the stage — what matters is that it is not `TlsUnsupported`, the downgrade-refusal kind.
        assert_ne!(failure.kind, SmtpFailureKind::TlsUnsupported);
        assert!(
            relay
                .transcript()
                .iter()
                .any(|line| line.eq_ignore_ascii_case("STARTTLS")),
            "STARTTLS was never sent: {:?}",
            relay.transcript()
        );
        // Credentials and envelope come strictly after the upgrade.
        assert_nothing_sensitive_on_the_wire(&relay);
    }

    /// A relay that does not offer STARTTLS while STARTTLS was configured is a hard failure, and —
    /// the part that matters — the client hangs up without having sent the password or the
    /// recipient in the clear.
    #[tokio::test]
    async fn a_relay_that_drops_starttls_is_refused_without_leaking_the_session() {
        let relay = FakeRelay::spawn(|line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                // Note: no STARTTLS. A downgrade attack looks exactly like this.
                "250-relay.example.pt\r\n250 AUTH PLAIN LOGIN\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let failure = client(relay.port, SmtpEncryption::StartTls, true)
            .send(&message())
            .await
            .expect_err("a silent downgrade must never happen");

        assert_eq!(failure.stage, SmtpStage::StartTls);
        assert_eq!(failure.kind, SmtpFailureKind::TlsUnsupported);
        assert!(!failure.tls, "the session was never encrypted: {failure:?}");
        assert_nothing_sensitive_on_the_wire(&relay);
    }

    /// CVE-2011-0411: a MITM pipelines plaintext behind the `220` so it lands in the client's buffer
    /// and is later read as though it had arrived inside the encrypted session. The client must
    /// refuse the upgrade rather than attribute those bytes to the server.
    #[tokio::test]
    async fn plaintext_pipelined_behind_the_starttls_reply_aborts_the_upgrade() {
        let relay = FakeRelay::spawn(|line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                EHLO_FULL.to_owned()
            } else if upper.starts_with("STARTTLS") {
                // One write, so both lines arrive in the same segment and the second is buffered.
                "220 Ready to start TLS\r\n250 Injected-by-a-mitm\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let failure = client(relay.port, SmtpEncryption::StartTls, true)
            .send(&message())
            .await
            .expect_err("injected plaintext must abort the upgrade");

        assert_eq!(failure.stage, SmtpStage::StartTls);
        assert_eq!(failure.kind, SmtpFailureKind::Protocol);
        assert!(
            failure.detail.contains("pipelined"),
            "the refusal must say what it saw: {}",
            failure.detail
        );
        assert_nothing_sensitive_on_the_wire(&relay);
    }

    // --- AUTH ----------------------------------------------------------------------------------

    /// `AUTH PLAIN` carries the RFC 4616 `authzid NUL authcid NUL passwd` triple, base64-encoded —
    /// asserted by decoding what the relay received, not by trusting that the call succeeded.
    #[tokio::test]
    async fn auth_plain_sends_the_rfc4616_triple() {
        let relay = FakeRelay::spawn(|line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                "250-relay.example.pt\r\n250 AUTH PLAIN\r\n".to_owned()
            } else if upper.starts_with("AUTH") {
                "235 2.7.0 Authentication successful\r\n".to_owned()
            } else if upper.starts_with("DATA") {
                "354 End data with <CR><LF>.<CR><LF>\r\n".to_owned()
            } else if upper.starts_with("QUIT") {
                "221 Bye\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let delivery = client(relay.port, SmtpEncryption::None, true)
            .send(&message())
            .await
            .expect("the relay accepts the message");
        assert!(delivery.authenticated);

        let auth = relay
            .transcript()
            .into_iter()
            .find(|line| line.to_ascii_uppercase().starts_with("AUTH "))
            .expect("an AUTH command was sent");
        let encoded = auth.split_whitespace().nth(2).expect("the base64 argument");
        let decoded = BASE64.decode(encoded).expect("base64");
        assert_eq!(
            decoded, b"\0sistema\0Palavra-Passe-Do-Relay-9!",
            "AUTH PLAIN must carry authzid NUL authcid NUL passwd"
        );
    }

    /// A relay offering only `LOGIN` gets the challenge/response exchange, each step base64 and in
    /// order — username first, then password, neither ever in the clear as text.
    #[tokio::test]
    async fn auth_login_answers_each_challenge_in_order() {
        let mut step = 0u8;
        let relay = FakeRelay::spawn(move |line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                // LOGIN only, so the PLAIN branch cannot be what runs.
                "250-relay.example.pt\r\n250 AUTH LOGIN\r\n".to_owned()
            } else if upper.starts_with("AUTH LOGIN") {
                step = 1;
                format!("334 {}\r\n", BASE64.encode("Username:"))
            } else if step == 1 {
                step = 2;
                format!("334 {}\r\n", BASE64.encode("Password:"))
            } else if step == 2 {
                step = 3;
                "235 2.7.0 Authentication successful\r\n".to_owned()
            } else if upper.starts_with("DATA") {
                "354 End data\r\n".to_owned()
            } else if upper.starts_with("QUIT") {
                "221 Bye\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let delivery = client(relay.port, SmtpEncryption::None, true)
            .send(&message())
            .await
            .expect("the relay accepts the message");
        assert!(delivery.authenticated);

        let transcript = relay.transcript();
        let start = transcript
            .iter()
            .position(|line| line.eq_ignore_ascii_case("AUTH LOGIN"))
            .expect("AUTH LOGIN was sent");
        let decode = |line: &String| {
            String::from_utf8(BASE64.decode(line.as_bytes()).expect("base64")).expect("utf-8")
        };
        assert_eq!(decode(&transcript[start + 1]), "sistema");
        assert_eq!(decode(&transcript[start + 2]), "Palavra-Passe-Do-Relay-9!");
        assert!(
            !relay.wire().contains("AUTH PLAIN"),
            "a LOGIN-only relay must not be offered PLAIN: {}",
            relay.wire()
        );
    }

    /// The interop rule: never negotiate a mechanism this client did not implement. A relay offering
    /// only XOAUTH2 and CRAM-MD5 gets a named refusal, and no credential material is put on the wire
    /// in a shape the client is guessing at.
    #[tokio::test]
    async fn an_unsupported_auth_mechanism_is_refused_by_name_rather_than_attempted() {
        let relay = FakeRelay::spawn(|line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                "250-relay.example.pt\r\n250 AUTH XOAUTH2 CRAM-MD5 NTLM\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let failure = client(relay.port, SmtpEncryption::None, true)
            .send(&message())
            .await
            .expect_err("an unimplemented mechanism must not be guessed at");

        assert_eq!(failure.stage, SmtpStage::Auth);
        assert_eq!(failure.kind, SmtpFailureKind::Configuration);
        // The operator has to be told which mechanisms this client can actually speak, or the
        // message is just "it did not work".
        assert!(
            failure.detail.contains("PLAIN") && failure.detail.contains("LOGIN"),
            "the refusal must name the supported mechanisms: {}",
            failure.detail
        );
        assert!(
            !relay.wire().to_ascii_uppercase().contains("AUTH"),
            "no AUTH command may be sent at all: {}",
            relay.wire()
        );
    }

    // --- Envelope and headers ------------------------------------------------------------------

    /// SMTPUTF8 is not implemented, so an internationalized envelope address is refused **before a
    /// socket is opened** — asserted against a live listener that records connections, so this is
    /// "nothing was attempted", not merely "an error came back".
    #[tokio::test]
    async fn a_non_ascii_envelope_address_is_refused_without_opening_a_connection() {
        let relay = FakeRelay::spawn(|_| Some("250 Ok\r\n".to_owned())).await;

        let failure = client(relay.port, SmtpEncryption::None, true)
            .send(&SmtpMessage {
                to_address: "amélia@encosto-estrategico.pt".to_owned(),
                ..message()
            })
            .await
            .expect_err("an EAI envelope address must be refused");

        assert_eq!(failure.stage, SmtpStage::Connect);
        assert_eq!(failure.kind, SmtpFailureKind::Configuration);
        assert!(failure.detail.contains("SMTPUTF8"), "{}", failure.detail);
        assert_eq!(
            relay.connections(),
            0,
            "the refusal must come before any socket is opened"
        );
        assert!(relay.transcript().is_empty());
    }

    /// The other half of the SMTPUTF8 rule: accented **display names and subjects** are header
    /// content, not envelope addresses, and must still be delivered — RFC 2047 encoded, with the
    /// ASCII envelope untouched.
    #[tokio::test]
    async fn accented_display_names_and_subjects_are_delivered_rfc2047_encoded() {
        let relay = FakeRelay::spawn(|line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                "250-relay.example.pt\r\n250 AUTH PLAIN\r\n".to_owned()
            } else if upper.starts_with("AUTH") {
                "235 2.7.0 Ok\r\n".to_owned()
            } else if upper.starts_with("DATA") {
                "354 End data\r\n".to_owned()
            } else if upper == "." {
                "250 2.0.0 Ok: queued as 8F2A1\r\n".to_owned()
            } else if upper.starts_with("QUIT") {
                "221 Bye\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let delivery = client(relay.port, SmtpEncryption::None, true)
            .send(&message())
            .await
            .expect("an accented display name is not an EAI address");
        assert_eq!(delivery.accepted_detail, "Ok: queued as 8F2A1");

        let wire = relay.wire();
        // The envelope stayed pure ASCII …
        assert!(
            wire.contains("MAIL FROM:<sistema@encosto-estrategico.pt>"),
            "{wire}"
        );
        assert!(
            wire.contains("RCPT TO:<amelia.marques@encosto-estrategico.pt>"),
            "{wire}"
        );
        // … and the accented header content travelled encoded, never as raw UTF-8 bytes.
        assert!(
            wire.contains("Subject: =?UTF-8?B?") && wire.contains("From: =?UTF-8?B?"),
            "accented headers must be RFC 2047 encoded on the wire: {wire}"
        );
        assert!(
            !wire.contains("Estratégico") && !wire.contains("configuração"),
            "no raw non-ASCII may reach the wire: {wire}"
        );
    }

    /// The whole reason this client is hand-rolled: the operator gets the relay's own answer. A
    /// generic "sending failed" would hide which of a dozen relay policies refused them.
    #[tokio::test]
    async fn a_rejection_surfaces_the_relays_own_code_and_text() {
        let relay = FakeRelay::spawn(|line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                "250-relay.example.pt\r\n250 AUTH PLAIN\r\n".to_owned()
            } else if upper.starts_with("AUTH") {
                "235 2.7.0 Ok\r\n".to_owned()
            } else if upper.starts_with("RCPT TO") {
                "550 5.7.1 Relay access denied for this recipient\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;

        let failure = client(relay.port, SmtpEncryption::None, true)
            .send(&message())
            .await
            .expect_err("the relay refused the recipient");

        // The stage is the fix: RCPT TO means relay policy, not a bad password.
        assert_eq!(failure.stage, SmtpStage::RcptTo);
        assert_eq!(failure.kind, SmtpFailureKind::Rejected);
        assert_eq!(failure.code, Some(550));
        assert_eq!(failure.enhanced_code.as_deref(), Some("5.7.1"));
        // The enhanced code is lifted into its own field rather than duplicated into the text, but
        // the operator-facing words are the relay's own, not a paraphrase.
        assert_eq!(
            failure.detail, "Relay access denied for this recipient",
            "the server's text is reported verbatim, not paraphrased"
        );
        assert_eq!(
            failure.summary(),
            "550 5.7.1: Relay access denied for this recipient"
        );
    }

    #[test]
    fn enhanced_code_is_recognised_only_in_its_real_shape() {
        assert_eq!(
            parse_enhanced_code("5.7.1 Relay access denied"),
            Some("5.7.1".to_owned())
        );
        assert_eq!(parse_enhanced_code("2.1.5 Ok"), Some("2.1.5".to_owned()));
        // A version-like token that is not an enhanced status class must not be mistaken for one.
        assert_eq!(parse_enhanced_code("1.2.3 nope"), None);
        assert_eq!(parse_enhanced_code("Relay access denied"), None);
        assert_eq!(parse_enhanced_code("5.7 truncated"), None);
    }

    #[test]
    fn failure_summary_carries_the_servers_real_code_and_text() {
        let failure = SmtpFailure {
            stage: SmtpStage::Auth,
            kind: SmtpFailureKind::Rejected,
            code: Some(535),
            enhanced_code: Some("5.7.8".to_owned()),
            detail: "Error: authentication failed".to_owned(),
            tls: true,
        };
        assert_eq!(failure.summary(), "535 5.7.8: Error: authentication failed");
    }

    #[test]
    fn capabilities_read_starttls_and_auth_mechanisms_case_insensitively() {
        let lines = vec![
            "relay.example.pt Hello".to_owned(),
            "PIPELINING".to_owned(),
            "starttls".to_owned(),
            "AUTH plain LOGIN".to_owned(),
        ];
        let caps = Capabilities::parse(&lines);
        assert!(caps.starttls);
        assert!(caps.auth_plain);
        assert!(caps.auth_login);
    }

    #[test]
    fn capabilities_ignore_the_greeting_line() {
        // A server whose greeting text happens to contain "STARTTLS" must not be read as offering it.
        let lines = vec!["relay.example.pt says STARTTLS".to_owned()];
        assert!(!Capabilities::parse(&lines).starttls);
    }

    #[test]
    fn rendered_message_is_base64_utf8_with_encoded_headers() {
        let rendered = render_message(&SmtpMessage {
            from_address: "sistema@encosto-estrategico.pt".to_owned(),
            from_name: Some("Encosto Estratégico Lda".to_owned()),
            to_address: "amelia.marques@encosto-estrategico.pt".to_owned(),
            subject: "Teste de configuração".to_owned(),
            body: "Olá — configuração validada.".to_owned(),
            html_body: None,
            date: "Mon, 20 Jul 2026 09:00:00 +0100".to_owned(),
            message_id: "abc@encosto-estrategico.pt".to_owned(),
        });
        assert!(rendered.contains("Content-Transfer-Encoding: base64\r\n"));
        assert!(rendered.contains("Auto-Submitted: auto-generated\r\n"));
        // Non-ASCII headers are RFC 2047 encoded rather than emitted raw.
        assert!(rendered.contains("Subject: =?UTF-8?B?"));
        assert!(rendered.contains("From: =?UTF-8?B?"));
        assert!(!rendered.contains("Estratégico <"));
        // The body round-trips.
        let body = rendered
            .split("\r\n\r\n")
            .nth(1)
            .expect("body")
            .replace("\r\n", "");
        let decoded = String::from_utf8(BASE64.decode(body).expect("base64")).expect("utf-8");
        assert_eq!(decoded, "Olá — configuração validada.");
    }

    #[tokio::test]
    async fn an_internationalized_envelope_address_is_refused_by_name_not_guessed() {
        let client = SmtpClient {
            host: "127.0.0.1".to_owned(),
            // Port 0 would fail to connect — the point is that it never gets that far.
            port: 0,
            encryption: SmtpEncryption::None,
            username: None,
            password: None,
            helo_name: "encosto-estrategico.pt".to_owned(),
        };
        let message = SmtpMessage {
            from_address: "sistema@encosto-estrategico.pt".to_owned(),
            from_name: Some("Encosto Estratégico Lda".to_owned()),
            // An EAI address needs SMTPUTF8, which this client does not implement.
            to_address: "amélia@encosto-estrategico.pt".to_owned(),
            subject: "Teste".to_owned(),
            body: "Olá".to_owned(),
            html_body: None,
            date: "Mon, 20 Jul 2026 09:00:00 +0100".to_owned(),
            message_id: "abc@chancela.invalid".to_owned(),
        };

        let failure = client.send(&message).await.expect_err("must refuse");
        assert_eq!(failure.kind, SmtpFailureKind::Configuration);
        assert!(
            failure.detail.contains("SMTPUTF8"),
            "the refusal must name the missing extension: {}",
            failure.detail
        );
        // An accented DISPLAY NAME is header content and stays perfectly fine.
        assert!(failure.detail.contains("to_address"));
    }

    #[test]
    fn ascii_headers_are_left_alone() {
        assert_eq!(encode_header_word("Test message"), "Test message");
    }

    /// `as_str` and the serde derive are two independent spellings of the same wire form, and they
    /// silently disagreed once (`snake_case` renders `StartTls` as `start_tls`). Pin every variant
    /// of both enums so a new one cannot reintroduce the split.
    #[test]
    fn serde_encoding_matches_as_str_for_every_variant() {
        for mode in [
            SmtpEncryption::StartTls,
            SmtpEncryption::ImplicitTls,
            SmtpEncryption::None,
        ] {
            assert_eq!(
                serde_json::to_value(mode).expect("serialize"),
                serde_json::Value::String(mode.as_str().to_owned()),
                "{mode:?} serializes differently from its as_str form"
            );
        }
        for stage in [
            SmtpStage::Connect,
            SmtpStage::Tls,
            SmtpStage::Greeting,
            SmtpStage::Ehlo,
            SmtpStage::StartTls,
            SmtpStage::Auth,
            SmtpStage::MailFrom,
            SmtpStage::RcptTo,
            SmtpStage::Data,
            SmtpStage::Quit,
        ] {
            assert_eq!(
                serde_json::to_value(stage).expect("serialize"),
                serde_json::Value::String(stage.as_str().to_owned()),
                "{stage:?} serializes differently from its as_str form"
            );
        }
        for kind in [
            SmtpFailureKind::Dns,
            SmtpFailureKind::Unreachable,
            SmtpFailureKind::Tls,
            SmtpFailureKind::TlsUnsupported,
            SmtpFailureKind::Timeout,
            SmtpFailureKind::Rejected,
            SmtpFailureKind::Protocol,
            SmtpFailureKind::Configuration,
        ] {
            assert_eq!(
                serde_json::to_value(kind).expect("serialize"),
                serde_json::Value::String(kind.as_str().to_owned()),
                "{kind:?} serializes differently from its as_str form"
            );
        }
    }

    #[test]
    fn encryption_modes_expose_stable_wire_forms_and_default_to_starttls() {
        assert_eq!(SmtpEncryption::default(), SmtpEncryption::StartTls);
        assert_eq!(SmtpEncryption::StartTls.as_str(), "starttls");
        assert_eq!(SmtpEncryption::ImplicitTls.as_str(), "implicit_tls");
        assert_eq!(SmtpEncryption::None.as_str(), "none");
        assert!(SmtpEncryption::StartTls.is_encrypted());
        assert!(SmtpEncryption::ImplicitTls.is_encrypted());
        assert!(!SmtpEncryption::None.is_encrypted());
    }

    // --- Multipart rendering (t70) ---------------------------------------------------------------

    #[test]
    fn a_message_with_an_html_body_is_multipart_alternative_with_both_parts_present() {
        let rendered = render_message(&multipart_message());

        assert!(
            rendered.contains("Content-Type: multipart/alternative; boundary=\""),
            "not multipart: {rendered}"
        );
        assert!(
            rendered.contains("Content-Type: text/plain; charset=utf-8"),
            "the text/plain part is missing — HTML-only mail is refused by gateways: {rendered}"
        );
        assert!(
            rendered.contains("Content-Type: text/html; charset=utf-8"),
            "the text/html part is missing: {rendered}"
        );

        // Both parts decode back to what went in.
        let boundary = multipart_boundary(&multipart_message().message_id);
        let parts: Vec<&str> = rendered.split(&format!("--{boundary}")).collect();
        assert_eq!(
            parts.len(),
            4,
            "expected preamble + 2 parts + closing delimiter, got {}: {rendered}",
            parts.len()
        );
        let decoded: Vec<String> = parts[1..3]
            .iter()
            .map(|part| {
                let body = part.split("\r\n\r\n").nth(1).expect("part body");
                let joined: String = body.split("\r\n").collect();
                String::from_utf8(BASE64.decode(joined.trim()).expect("base64")).expect("utf8")
            })
            .collect();
        assert_eq!(decoded[0], multipart_message().body);
        assert_eq!(decoded[1], multipart_message().html_body.unwrap());
    }

    /// RFC 2046 §5.1.4: a client displays the **last** part it understands, so the plain-text part
    /// has to come first or a text-only client picks nothing. Getting this backwards is the classic
    /// multipart bug and it is invisible in any client that does understand HTML.
    #[test]
    fn the_plain_text_part_precedes_the_html_part() {
        let rendered = render_message(&multipart_message());
        let text_at = rendered
            .find("Content-Type: text/plain")
            .expect("text part present");
        let html_at = rendered
            .find("Content-Type: text/html")
            .expect("html part present");
        assert!(
            text_at < html_at,
            "the HTML part precedes the text part, so a text-only client would show nothing"
        );
    }

    /// A message with no HTML stays a simple `text/plain` message rather than growing a pointless
    /// one-part multipart wrapper.
    #[test]
    fn a_message_without_an_html_body_stays_single_part() {
        let rendered = render_message(&message());
        assert!(!rendered.contains("multipart"), "{rendered}");
        assert!(rendered.contains("Content-Type: text/plain; charset=utf-8"));
    }

    /// The boundary must not be able to appear inside a part, or the message truncates at whatever
    /// line collided. Both parts are base64, whose alphabet excludes `_` entirely.
    #[test]
    fn the_multipart_boundary_cannot_collide_with_base64_body_lines() {
        let boundary = multipart_boundary(&multipart_message().message_id);
        assert!(boundary.contains('_'), "{boundary}");
        // `_` and `=` are outside the base64 alphabet (bar terminal padding), so no encoded body
        // line can begin with the delimiter.
        assert!(!boundary.chars().all(|c| c.is_ascii_alphanumeric()));
        let rendered = render_message(&multipart_message());
        // Exactly three delimiter occurrences: two opening, one closing.
        assert_eq!(rendered.matches(&format!("--{boundary}")).count(), 3);
    }

    /// The accented-subject path is unchanged by multipart. Pinned because `Subject:` moved relative
    /// to the `Content-Type` header when the multipart branch was added.
    #[test]
    fn an_accented_subject_is_still_rfc_2047_encoded_in_a_multipart_message() {
        let rendered = render_message(&multipart_message());
        let expected = format!(
            "Subject: =?UTF-8?B?{}?=",
            BASE64.encode("Teste de configuração".as_bytes())
        );
        assert!(
            rendered.contains(&expected),
            "the accented subject was not RFC 2047 encoded: {rendered}"
        );
        // And the display name in `From:`, which is the other header that carries free text.
        assert!(
            rendered.contains(&format!(
                "=?UTF-8?B?{}?=",
                BASE64.encode("Encosto Estratégico Lda".as_bytes())
            )),
            "the accented display name was not RFC 2047 encoded: {rendered}"
        );
    }

    // --- The diagnostic trace (t70) ---------------------------------------------------------------

    #[tokio::test]
    async fn the_trace_records_the_whole_protocol_timeline_on_success() {
        let relay = FakeRelay::spawn(accepting_reply).await;
        let client = client(relay.port, SmtpEncryption::None, true);
        let (outcome, trace) = client
            .send_traced_with_roots(&multipart_message(), &TestRoots)
            .await;
        assert!(outcome.is_ok(), "{outcome:?}");

        let stages: Vec<SmtpStage> = trace.steps.iter().map(|s| s.stage).collect();
        assert_eq!(
            stages,
            vec![
                SmtpStage::Connect,
                SmtpStage::Greeting,
                SmtpStage::Ehlo,
                SmtpStage::StartTls, // skipped, but recorded
                SmtpStage::Auth,
                SmtpStage::MailFrom,
                SmtpStage::RcptTo,
                SmtpStage::Data,
                SmtpStage::Quit,
            ],
            "the timeline should show every stage, including the ones not attempted"
        );

        // A stage that was not attempted is `Skipped` and says why, rather than being absent.
        let starttls = trace
            .steps
            .iter()
            .find(|s| s.stage == SmtpStage::StartTls)
            .expect("starttls step");
        assert_eq!(starttls.outcome, SmtpStepOutcome::Skipped);
        assert!(
            starttls
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("none")),
            "a skipped stage should explain itself: {starttls:?}"
        );

        // The resolved address, so a hostname pointing somewhere unexpected is visible.
        assert_eq!(
            trace.resolved_address.as_deref(),
            Some(format!("127.0.0.1:{}", relay.port).as_str())
        );
        assert_eq!(trace.port, relay.port);
        assert!(!trace.tls_established);
        assert_eq!(trace.auth_mechanism.as_deref(), Some("PLAIN"));
        // The relay's advertised extensions, verbatim — "offered no AUTH" and "offered only
        // CRAM-MD5" are different problems with the same symptom.
        assert!(
            trace
                .advertised_capabilities
                .iter()
                .any(|c| c == "AUTH PLAIN LOGIN"),
            "{:?}",
            trace.advertised_capabilities
        );
        // The relay's own accepting reply reached the timeline.
        let data = trace
            .steps
            .iter()
            .find(|s| s.stage == SmtpStage::Data)
            .expect("data step");
        assert_eq!(data.code, Some(250));
        assert!(
            data.detail.as_deref().is_some_and(|d| d.contains("8F2A1")),
            "the relay's queue id should survive into the trace: {data:?}"
        );
    }

    /// The single most useful thing in the payload: the server's real code and text at the stage
    /// that failed. This is the reason a generic "could not send" is useless.
    #[tokio::test]
    async fn the_trace_carries_the_servers_verbatim_reply_at_the_failing_stage() {
        let relay = FakeRelay::spawn(|line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                EHLO_FULL.to_owned()
            } else if upper.starts_with("AUTH") {
                "535 5.7.8 Error: authentication failed: bad credentials\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;
        let client = client(relay.port, SmtpEncryption::None, true);
        let (outcome, trace) = client
            .send_traced_with_roots(&multipart_message(), &TestRoots)
            .await;
        assert!(outcome.is_err());

        let auth = trace
            .steps
            .iter()
            .find(|s| s.stage == SmtpStage::Auth)
            .expect("auth step");
        assert_eq!(auth.outcome, SmtpStepOutcome::Failed);
        assert_eq!(auth.code, Some(535));
        assert_eq!(auth.enhanced_code.as_deref(), Some("5.7.8"));
        assert_eq!(
            auth.detail.as_deref(),
            Some("Error: authentication failed: bad credentials"),
            "the server's text must survive verbatim"
        );

        // Stages after the failure are simply absent — the timeline stops where the session did.
        assert!(
            !trace.steps.iter().any(|s| s.stage == SmtpStage::MailFrom),
            "the timeline should stop at the failure, not invent later stages"
        );

        // And the raw server line is in the transcript too.
        assert!(
            trace.transcript.iter().any(|l| {
                l.direction == SmtpTranscriptDirection::Server
                    && l.text.contains("535 5.7.8 Error: authentication failed")
            }),
            "{:?}",
            trace.transcript
        );
    }

    /// A refusal by *this client* is not the relay's fault, and is reported as a distinct outcome so
    /// the operator looks in the right place.
    #[tokio::test]
    async fn a_client_side_refusal_is_recorded_as_refused_not_failed() {
        // A relay that offers no AUTH mechanism we implement, while a username is configured.
        let relay = FakeRelay::spawn(|line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                "250-relay.example.pt\r\n250 AUTH CRAM-MD5 XOAUTH2\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;
        let client = client(relay.port, SmtpEncryption::None, true);
        let (outcome, trace) = client
            .send_traced_with_roots(&multipart_message(), &TestRoots)
            .await;
        assert!(outcome.is_err());

        let auth = trace
            .steps
            .iter()
            .find(|s| s.stage == SmtpStage::Auth)
            .expect("auth step");
        assert_eq!(
            auth.outcome,
            SmtpStepOutcome::Refused,
            "an unimplemented AUTH mechanism is this client declining, not the relay erroring"
        );
        assert!(
            auth.detail
                .as_deref()
                .is_some_and(|d| d.contains("PLAIN or LOGIN")),
            "the refusal should name what is supported: {auth:?}"
        );
        // What the relay *did* offer is in the trace, which is how the operator sees the mismatch.
        assert!(
            trace
                .advertised_capabilities
                .iter()
                .any(|c| c.contains("CRAM-MD5")),
            "{:?}",
            trace.advertised_capabilities
        );
    }

    /// Timing is per stage so a hang is distinguishable from a refusal.
    #[tokio::test]
    async fn every_step_carries_its_own_timing() {
        let relay = FakeRelay::spawn(accepting_reply).await;
        let client = client(relay.port, SmtpEncryption::None, true);
        let (_, trace) = client
            .send_traced_with_roots(&multipart_message(), &TestRoots)
            .await;

        for step in &trace.steps {
            assert!(
                step.started_ms <= trace.total_ms,
                "{step:?} starts after the session ended (total {}ms)",
                trace.total_ms
            );
        }
        // The timeline is ordered, which is what makes it readable as a timeline.
        let mut previous = 0;
        for step in &trace.steps {
            assert!(step.started_ms >= previous, "out of order: {step:?}");
            previous = step.started_ms;
        }
        assert!(trace.transcript.iter().all(|l| l.at_ms <= trace.total_ms));
    }

    // --- Password redaction (t70) -----------------------------------------------------------------

    /// **The load-bearing security test.** A relay that echoes the credential back — pathological,
    /// but the only case the structural redaction cannot cover, because server replies are recorded
    /// verbatim by design — must still not put the password in the payload.
    ///
    /// Asserts against the *serialized* trace, which is what actually reaches the browser, and
    /// checks the plaintext and both base64 forms, since on the wire the password only ever appears
    /// encoded.
    #[tokio::test]
    async fn the_password_appears_nowhere_in_the_trace_even_when_the_relay_echoes_it() {
        let password = "Palavra-Passe-Do-Relay-9!";
        let plain_blob = {
            let mut raw = Vec::new();
            raw.push(0);
            raw.extend_from_slice(b"sistema");
            raw.push(0);
            raw.extend_from_slice(password.as_bytes());
            BASE64.encode(&raw)
        };
        let login_blob = BASE64.encode(password.as_bytes());

        // This relay is hostile: it quotes the client's AUTH line straight back in its reply text.
        let relay = FakeRelay::spawn(move |line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                EHLO_FULL.to_owned()
            } else if upper.starts_with("AUTH") {
                format!("535 5.7.8 rejected credentials: you sent {line}\r\n")
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;
        let client = client(relay.port, SmtpEncryption::None, true);
        let (outcome, trace) = client
            .send_traced_with_roots(&multipart_message(), &TestRoots)
            .await;
        assert!(outcome.is_err());

        let serialized = serde_json::to_string(&trace).expect("serialize trace");
        for (needle, what) in [
            (password, "the plaintext password"),
            (plain_blob.as_str(), "the AUTH PLAIN base64 blob"),
            (login_blob.as_str(), "the AUTH LOGIN base64 password"),
        ] {
            assert!(
                !serialized.contains(needle),
                "{what} leaked into the serialized trace: {serialized}"
            );
        }
        // It was genuinely exercised: the relay did echo something, and it came back redacted.
        assert!(
            serialized.contains(REDACTED),
            "the echo path was not exercised, so this test proved nothing: {serialized}"
        );
        // The diagnostic value survives the redaction — the code and the rest of the text remain.
        let auth = trace
            .steps
            .iter()
            .find(|s| s.stage == SmtpStage::Auth)
            .expect("auth step");
        assert_eq!(auth.code, Some(535));
        assert!(
            auth.detail
                .as_deref()
                .is_some_and(|d| d.contains("rejected credentials")),
            "{auth:?}"
        );
    }

    /// The structural half: the client's own AUTH lines are recorded as fixed placeholders, so the
    /// credential never reaches the recorder at all — the scrub above is the second line of defence,
    /// not the first.
    #[tokio::test]
    async fn the_transcript_shows_auth_as_a_placeholder_rather_than_a_base64_blob() {
        let relay = FakeRelay::spawn(accepting_reply).await;
        let client = client(relay.port, SmtpEncryption::None, true);
        let (outcome, trace) = client
            .send_traced_with_roots(&multipart_message(), &TestRoots)
            .await;
        assert!(outcome.is_ok(), "{outcome:?}");

        let client_lines: Vec<&str> = trace
            .transcript
            .iter()
            .filter(|l| l.direction == SmtpTranscriptDirection::Client)
            .map(|l| l.text.as_str())
            .collect();
        assert!(
            client_lines.contains(&"AUTH PLAIN <redacted>"),
            "{client_lines:?}"
        );
        // The non-secret conversation is still there verbatim — that is the point of a transcript.
        assert!(
            client_lines
                .iter()
                .any(|l| l.starts_with("MAIL FROM:<sistema@")),
            "{client_lines:?}"
        );
        assert!(
            client_lines.iter().any(|l| l.starts_with("EHLO ")),
            "{client_lines:?}"
        );
        // The message body is summarized rather than reproduced, so a trace pasted into a support
        // ticket does not carry the recipient's message text with it.
        assert!(
            client_lines.iter().any(|l| l.starts_with("<message body:")),
            "{client_lines:?}"
        );
        assert!(
            !client_lines
                .iter()
                .any(|l| l.contains("configuração validada")),
            "the message body leaked into the transcript: {client_lines:?}"
        );
    }

    /// `AUTH LOGIN` sends the credential as a bare continuation line with no verb to key off, so it
    /// is the easiest of the two mechanisms to leak. Covered separately for that reason.
    #[tokio::test]
    async fn the_auth_login_mechanism_redacts_both_challenge_responses() {
        // AUTH LOGIN is a three-legged exchange: `AUTH LOGIN` → 334, username → 334, password →
        // 235. The relay has to count its own legs, since the two credential lines are bare base64
        // with no verb to match on — which is precisely why they are the easy ones to leak.
        let mut auth_leg = 0;
        let relay = FakeRelay::spawn(move |line| {
            let upper = line.to_ascii_uppercase();
            Some(if upper.starts_with("EHLO") {
                // LOGIN only, so the client cannot choose PLAIN.
                "250-relay.example.pt\r\n250 AUTH LOGIN\r\n".to_owned()
            } else if upper.starts_with("AUTH LOGIN") {
                auth_leg = 1;
                "334 VXNlcm5hbWU6\r\n".to_owned()
            } else if auth_leg == 1 {
                auth_leg = 2;
                "334 UGFzc3dvcmQ6\r\n".to_owned()
            } else if auth_leg == 2 {
                auth_leg = 3;
                "235 2.7.0 Authentication successful\r\n".to_owned()
            } else if upper.starts_with("DATA") {
                "354 End data\r\n".to_owned()
            } else if line == "." {
                "250 2.0.0 Ok: queued\r\n".to_owned()
            } else {
                "250 Ok\r\n".to_owned()
            })
        })
        .await;
        let client = client(relay.port, SmtpEncryption::None, true);
        let (_, trace) = client
            .send_traced_with_roots(&multipart_message(), &TestRoots)
            .await;

        assert_eq!(trace.auth_mechanism.as_deref(), Some("LOGIN"));
        let serialized = serde_json::to_string(&trace).expect("serialize");
        assert!(
            !serialized.contains(&BASE64.encode("Palavra-Passe-Do-Relay-9!".as_bytes())),
            "the AUTH LOGIN password blob leaked: {serialized}"
        );
        let client_lines: Vec<&str> = trace
            .transcript
            .iter()
            .filter(|l| l.direction == SmtpTranscriptDirection::Client)
            .map(|l| l.text.as_str())
            .collect();
        assert!(client_lines.contains(&"<redacted>"), "{client_lines:?}");
        assert!(
            client_lines.contains(&"<username, base64>"),
            "{client_lines:?}"
        );
    }

    /// The recorder holds the password as scrub needles, so its `Debug` is the one place it could
    /// reach a log line or a panic message. Written by hand; pinned here.
    #[test]
    fn the_recorders_debug_output_does_not_contain_the_needles() {
        let password = Zeroizing::new("Palavra-Passe-Do-Relay-9!".to_owned());
        let rec = Recorder::new(Some("sistema"), Some(&password));
        let debug = format!("{rec:?}");
        assert!(!debug.contains("Palavra-Passe"), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");
    }

    /// The wire form is a contract with `SMTP_STEP_OUTCOMES` in `apps/web/src/api/types.ts`, and
    /// `rename_all = "snake_case"` is exactly what turned `StartTls` into `start_tls` behind t23's
    /// back. Pinned against literals so a variant rename cannot quietly change the JSON.
    #[test]
    fn step_outcome_serde_encoding_is_stable() {
        for (outcome, expected) in [
            (SmtpStepOutcome::Ok, "ok"),
            (SmtpStepOutcome::Failed, "failed"),
            (SmtpStepOutcome::Skipped, "skipped"),
            (SmtpStepOutcome::Refused, "refused"),
        ] {
            assert_eq!(
                serde_json::to_value(outcome).expect("serialize"),
                serde_json::Value::String(expected.to_owned()),
                "{outcome:?} no longer serializes as {expected:?}, which the web union expects"
            );
        }
    }
}
