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
use std::time::Duration;

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
    /// UTF-8 plain-text body.
    pub body: String,
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
                    format!("timed out after {}s waiting for a reply", STEP_TIMEOUT.as_secs()),
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

    /// Write a line and read the reply. `verb` is used only for error text; command *arguments* are
    /// never echoed, so an `AUTH` line can never leak into a message.
    async fn command(
        &mut self,
        stage: SmtpStage,
        line: &str,
    ) -> Result<SmtpReply, SmtpFailure> {
        self.write_line(stage, line).await?;
        self.read_reply(stage).await
    }

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
                format!("timed out after {}s sending a command", STEP_TIMEOUT.as_secs()),
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
        // Refuse before opening a socket, rather than negotiate something we did not implement.
        Self::reject_unimplemented(message)?;
        // `connect` failing means we never had a session at all, so `tls: false` (already the
        // constructors' default) is accurate — including for a failed implicit-TLS handshake.
        let mut session = self.connect().await?;
        // Everything after this point runs inside a live session, so the failure's `tls` flag is
        // stamped from that session rather than defaulted. One place, so no path can forget.
        self.deliver(&mut session, message).await.map_err(|mut e| {
            e.tls = session.tls;
            e
        })
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
    ) -> Result<SmtpDelivery, SmtpFailure> {
        // Opening banner.
        let greeting = session.read_reply(SmtpStage::Greeting).await?;
        Session::expect_positive(greeting, SmtpStage::Greeting)?;

        let mut caps = self.ehlo(session).await?;

        if self.encryption == SmtpEncryption::StartTls {
            if !caps.starttls {
                return Err(SmtpFailure::new(
                    SmtpStage::StartTls,
                    SmtpFailureKind::TlsUnsupported,
                    "the server did not advertise STARTTLS, so the connection cannot be encrypted; \
                     fix the relay, use implicit TLS on port 465, or explicitly select no \
                     encryption",
                ));
            }
            self.start_tls(session).await?;
            // Capabilities before and after the upgrade are independent; only the encrypted set counts.
            caps = self.ehlo(session).await?;
        }

        let authenticated = self.authenticate(session, &caps).await?;

        // Envelope. A rejection at MAIL FROM is a sender the relay will not accept; at RCPT TO it is
        // usually relay denial. Reporting them under distinct stages is the whole point.
        let mail_from = session
            .command(
                SmtpStage::MailFrom,
                &format!("MAIL FROM:<{}>", message.from_address),
            )
            .await?;
        Session::expect_positive(mail_from, SmtpStage::MailFrom)?;

        let rcpt_to = session
            .command(
                SmtpStage::RcptTo,
                &format!("RCPT TO:<{}>", message.to_address),
            )
            .await?;
        Session::expect_positive(rcpt_to, SmtpStage::RcptTo)?;

        // DATA: a 354 intermediate, then the body, then the terminating dot.
        let data = session.command(SmtpStage::Data, "DATA").await?;
        if data.code != 354 {
            return Err(SmtpFailure::from_reply(SmtpStage::Data, &data));
        }
        let body = render_message(message);
        session.write_line(SmtpStage::Data, &body).await?;
        let accepted = session.command(SmtpStage::Data, ".").await?;
        let accepted = Session::expect_positive(accepted, SmtpStage::Data)?;

        // QUIT is best-effort: the relay already accepted the message, so a failure to say goodbye
        // must not be reported as a delivery failure.
        let _ = session.command(SmtpStage::Quit, "QUIT").await;

        Ok(SmtpDelivery {
            tls: session.tls,
            authenticated,
            accepted_detail: accepted.text,
        })
    }

    async fn connect(&self) -> Result<Session, SmtpFailure> {
        let address = format!("{}:{}", self.host, self.port);
        let tcp = tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect(&address))
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
            })?
            .map_err(|e| {
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
            })?;

        let stream = if self.encryption == SmtpEncryption::ImplicitTls {
            SmtpStream::Tls(Box::new(self.handshake(tcp).await?))
        } else {
            SmtpStream::Plain(tcp)
        };
        let tls = self.encryption == SmtpEncryption::ImplicitTls;
        Ok(Session {
            stream: BufReader::new(stream),
            tls,
        })
    }

    async fn handshake(&self, tcp: TcpStream) -> Result<TlsStream<TcpStream>, SmtpFailure> {
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
        let connector = TlsConnector::from(tls_config()?);
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
        let reply = session
            .command(SmtpStage::Ehlo, &format!("EHLO {}", self.helo_name))
            .await?;
        let reply = Session::expect_positive(reply, SmtpStage::Ehlo)?;
        Ok(Capabilities::parse(&reply.lines))
    }

    async fn start_tls(&self, session: &mut Session) -> Result<(), SmtpFailure> {
        let reply = session.command(SmtpStage::StartTls, "STARTTLS").await?;
        Session::expect_positive(reply, SmtpStage::StartTls)?;

        // STARTTLS response injection (CVE-2011-0411): anything already buffered was sent before the
        // handshake and must not be trusted as part of the encrypted session.
        if !session.stream.buffer().is_empty() {
            return Err(SmtpFailure::new(
                SmtpStage::StartTls,
                SmtpFailureKind::Protocol,
                "the server pipelined data after its STARTTLS reply; refusing the upgrade because \
                 that plaintext could be injected into the encrypted session",
            ));
        }

        let SmtpStream::Plain(tcp) =
            std::mem::replace(session.stream.get_mut(), SmtpStream::Upgrading)
        else {
            return Err(SmtpFailure::new(
                SmtpStage::StartTls,
                SmtpFailureKind::Protocol,
                "the connection was already encrypted when STARTTLS was attempted",
            ));
        };

        // On handshake failure the session is dropped by the caller, so the `Upgrading` placeholder
        // is never read from.
        let tls = self.handshake(tcp).await?;
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
            return Ok(false);
        };
        if username.is_empty() {
            return Ok(false);
        }
        if !caps.auth_plain && !caps.auth_login {
            return Err(SmtpFailure::new(
                SmtpStage::Auth,
                SmtpFailureKind::Configuration,
                "a username is configured but the server advertised no AUTH mechanism this client \
                 supports (PLAIN or LOGIN); if the relay needs no credentials, clear the username",
            ));
        }

        let reply = if caps.auth_plain {
            // RFC 4616: authzid NUL authcid NUL passwd, base64. Zeroized after encoding.
            let mut raw = Zeroizing::new(Vec::new());
            raw.push(0);
            raw.extend_from_slice(username.as_bytes());
            raw.push(0);
            raw.extend_from_slice(password.as_bytes());
            let encoded = Zeroizing::new(BASE64.encode(&*raw));
            session
                .command(SmtpStage::Auth, &format!("AUTH PLAIN {}", *encoded))
                .await?
        } else {
            let start = session.command(SmtpStage::Auth, "AUTH LOGIN").await?;
            if start.code != 334 {
                return Err(SmtpFailure::from_reply(SmtpStage::Auth, &start));
            }
            let user_reply = session
                .command(SmtpStage::Auth, &BASE64.encode(username.as_bytes()))
                .await?;
            if user_reply.code != 334 {
                return Err(SmtpFailure::from_reply(SmtpStage::Auth, &user_reply));
            }
            let encoded = Zeroizing::new(BASE64.encode(password.as_bytes()));
            session.command(SmtpStage::Auth, &encoded).await?
        };

        // A 535 here is the single most common real-world mail misconfiguration. The server's own
        // text ("authentication failed", "Username and Password not accepted", …) is what the
        // operator needs, so it is reported verbatim.
        Session::expect_positive(reply, SmtpStage::Auth)?;
        Ok(true)
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
    let config =
        ClientConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
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
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: base64\r\n");
    out.push_str("Auto-Submitted: auto-generated\r\n");
    out.push_str("\r\n");
    let encoded = BASE64.encode(message.body.as_bytes());
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str("\r\n");
    }
    // Base64 output can never begin a line with '.', so no dot-stuffing pass is needed; the
    // terminating "." is written by the caller as its own command.
    out.trim_end_matches("\r\n").to_owned()
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
    use super::*;

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
        assert_eq!(
            failure.summary(),
            "535 5.7.8: Error: authentication failed"
        );
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
}
