//! Rustls-based TLS for the synchronous Postgres backend (wp25).
//!
//! The Postgres arm ([`crate::pg`]) is deliberately synchronous — the frozen `persist(|tx| …)`
//! closure API is preserved verbatim, so the backend is built on the sync `postgres` crate + `r2d2`
//! rather than an async pool (plan §2.3 Option A). This module supplies the TLS half without leaving
//! that model: it implements the `postgres`/`tokio-postgres` [`MakeTlsConnect`] / [`TlsConnect`] /
//! [`TlsStream`] traits over `tokio-rustls`, reusing the rustls stack already compiled into the
//! workspace, so **no `postgres-native-tls` / `postgres-openssl` (OpenSSL) dependency is pulled in**.
//! The connector plugs into both the read pool (`PostgresConnectionManager::new(config, connector)`)
//! and the single advisory-locked writer (`config.connect(connector)`).
//!
//! ## Modes ([`PgSslMode`])
//!
//! The desired mode is resolved from `CHANCELA_PG_SSLMODE` (highest precedence) or the `sslmode=`
//! parameter of `DATABASE_URL`, defaulting to `verify-full`. Insecure libpq-compatible modes are
//! parsed only so this layer can reject them with a clear fail-closed error:
//!
//! - **`disable`** — rejected; it would send credentials and store traffic in plaintext.
//! - **`prefer`** — rejected; it can fall back to plaintext and does not authenticate the server.
//! - **`require`** — rejected; it encrypts but does not authenticate the server certificate.
//! - **`verify-full`** (also accepts `verify-ca`, hardened to `verify-full`) — the connection must be
//!   encrypted **and** the server certificate is verified against a root CA (from
//!   `CHANCELA_PG_TLS_ROOT_CERT`, else the OS trust store) with hostname checking.
//!
//! ## Channel binding
//!
//! [`TlsStream::channel_binding`] returns [`ChannelBinding::none`], so SCRAM-SHA-256**-PLUS** channel
//! binding is not negotiated; authentication uses plain SCRAM-SHA-256 over the TLS channel. TLS still
//! fully encrypts the session and (under `verify-full`) authenticates the server. This is a
//! deliberate, documented simplification, not a silent gap.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use postgres::Socket;
use postgres::config::{Config, SslMode};
use postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::StoreError;

/// Env override for the effective sslmode; wins over any `sslmode=` in `DATABASE_URL`.
pub(crate) const SSLMODE_ENV: &str = "CHANCELA_PG_SSLMODE";
/// Env pointing at a PEM file of root CA certificate(s) trusted for `verify-full`. When unset the
/// OS trust store is used.
pub(crate) const ROOT_CERT_ENV: &str = "CHANCELA_PG_TLS_ROOT_CERT";

/// The resolved TLS posture for a Postgres connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PgSslMode {
    /// No TLS (historical `NoTls`): plaintext and therefore rejected for Chancela startup.
    Disable,
    /// Opportunistic TLS: may fall back to plaintext and is therefore rejected.
    Prefer,
    /// Mandatory TLS without server authentication; rejected because active MITM remains possible.
    Require,
    /// Mandatory TLS with root-CA + hostname verification.
    VerifyFull,
}

impl PgSslMode {
    /// Parse a libpq-style sslmode token. `verify-ca` is treated as `verify-full` (stricter is
    /// safe). Returns `None` for tokens this backend does not implement (e.g. `allow`).
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "disable" => Some(Self::Disable),
            "prefer" => Some(Self::Prefer),
            "require" => Some(Self::Require),
            "verify-ca" | "verify-full" => Some(Self::VerifyFull),
            _ => None,
        }
    }

    /// The tokio-postgres [`SslMode`] that drives whether an SSLRequest is sent and whether TLS is
    /// mandatory. `verify-full` maps to `Require` at the protocol level; the extra certificate
    /// verification is enforced by the rustls verifier, not the wire mode.
    fn wire_mode(self) -> SslMode {
        match self {
            Self::Disable => SslMode::Disable,
            Self::Prefer => SslMode::Prefer,
            Self::Require | Self::VerifyFull => SslMode::Require,
        }
    }

    /// Whether the server certificate must be validated (root CA + hostname).
    fn verifies(self) -> bool {
        matches!(self, Self::VerifyFull)
    }
}

/// A fully resolved connection: a sanitized [`Config`] (with `ssl_mode` set programmatically) plus
/// the rustls connector to pass to both the pool manager and the writer `connect`.
pub(crate) struct ResolvedPgTls {
    pub(crate) config: Config,
    pub(crate) connector: MakeRustlsConnect,
    pub(crate) mode: PgSslMode,
}

/// Resolve the TLS posture for `database_url` and build the matching connector.
///
/// Precedence: `CHANCELA_PG_SSLMODE` → the URL's `sslmode=` → `verify-full`. Any `sslmode=` is stripped
/// from the string before it is handed to [`Config`] (which cannot parse `verify-full`/`verify-ca`),
/// and the wire [`SslMode`] is then set programmatically so all four modes are honored uniformly.
pub(crate) fn resolve(database_url: &str) -> Result<ResolvedPgTls, StoreError> {
    let (url_sslmode, stripped) = extract_and_strip_sslmode(database_url);

    let mode = match std::env::var(SSLMODE_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        Some(raw) => PgSslMode::parse(&raw).ok_or_else(|| {
            StoreError::PgTls(format!(
                "{SSLMODE_ENV}={raw:?} is not a supported sslmode \
                 (use disable|prefer|require|verify-ca|verify-full)"
            ))
        })?,
        None => match url_sslmode {
            Some(raw) => PgSslMode::parse(&raw).ok_or_else(|| {
                StoreError::PgTls(format!(
                    "sslmode={raw:?} in DATABASE_URL is not a supported sslmode \
                     (use disable|prefer|require|verify-ca|verify-full)"
                ))
            })?,
            None => PgSslMode::VerifyFull,
        },
    };

    if !mode.verifies() {
        return Err(StoreError::PgTls(format!(
            "PostgreSQL sslmode must be verify-full (verify-ca is accepted and hardened to \"verify-full\"); \
             insecure sslmode={mode:?} is not allowed because it permits plaintext or \
             unauthenticated database transport"
        )));
    }

    let mut config: Config = stripped.parse().map_err(StoreError::Postgres)?;
    config.ssl_mode(mode.wire_mode());

    let connector = MakeRustlsConnect::build(mode)?;
    Ok(ResolvedPgTls {
        config,
        connector,
        mode,
    })
}

/// Split a libpq DSN into `(sslmode-value, dsn-without-sslmode)`. Handles both the `postgres://…`
/// URL query form (`?sslmode=…&…`) and the libpq keyword form (`host=… sslmode=…`). Keyword values
/// may be single-quoted and contain whitespace; non-`sslmode` tokens are preserved as whole
/// key/value assignments rather than split on inner quoted spaces. The raw value is returned
/// uninterpreted so [`resolve`] can reject unknown modes explicitly rather than silently dropping
/// them.
fn extract_and_strip_sslmode(dsn: &str) -> (Option<String>, String) {
    if dsn.contains("://") {
        let Some(qpos) = dsn.find('?') else {
            return (None, dsn.to_owned());
        };
        let base = &dsn[..qpos];
        let query = &dsn[qpos + 1..];
        let mut kept: Vec<&str> = Vec::new();
        let mut found: Option<String> = None;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let key = pair.split('=').next().unwrap_or(pair);
            if key.eq_ignore_ascii_case("sslmode") {
                found = Some(
                    pair.split_once('=')
                        .map(|(_, v)| v)
                        .unwrap_or("")
                        .to_owned(),
                );
            } else {
                kept.push(pair);
            }
        }
        let rebuilt = if kept.is_empty() {
            base.to_owned()
        } else {
            format!("{base}?{}", kept.join("&"))
        };
        return (found, rebuilt);
    }

    // libpq keyword/value form. Values can be single-quoted and may contain escaped spaces or
    // quotes, so tokenizing with `split_whitespace` would corrupt valid DSNs.
    strip_keyword_sslmode(dsn)
}

fn strip_keyword_sslmode(dsn: &str) -> (Option<String>, String) {
    let bytes = dsn.as_bytes();
    let mut pos = 0usize;
    let mut kept: Vec<&str> = Vec::new();
    let mut found: Option<String> = None;

    while pos < bytes.len() {
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }

        let token_start = pos;
        let key_start = pos;
        while pos < bytes.len() && bytes[pos] != b'=' && !bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }

        if pos >= bytes.len() || bytes[pos] != b'=' {
            while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            kept.push(&dsn[token_start..pos]);
            continue;
        }

        let key = &dsn[key_start..pos];
        pos += 1;

        let (value, token_end, closed_quote) = if pos < bytes.len() && bytes[pos] == b'\'' {
            read_quoted_keyword_value(dsn, pos + 1)
        } else {
            let value_start = pos;
            while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            (dsn[value_start..pos].to_owned(), pos, true)
        };

        if !closed_quote {
            return (None, dsn.to_owned());
        }
        pos = token_end;

        if key.eq_ignore_ascii_case("sslmode") {
            found = Some(value);
        } else {
            kept.push(&dsn[token_start..token_end]);
        }
    }

    (found, kept.join(" "))
}

fn read_quoted_keyword_value(dsn: &str, mut pos: usize) -> (String, usize, bool) {
    let bytes = dsn.as_bytes();
    let mut value = String::new();

    while pos < bytes.len() {
        match bytes[pos] {
            b'\'' => return (value, pos + 1, true),
            b'\\' => {
                pos += 1;
                if pos >= bytes.len() {
                    value.push('\\');
                    return (value, pos, false);
                }
                let ch = dsn[pos..].chars().next().expect("valid utf-8 boundary");
                value.push(ch);
                pos += ch.len_utf8();
            }
            _ => {
                let ch = dsn[pos..].chars().next().expect("valid utf-8 boundary");
                value.push(ch);
                pos += ch.len_utf8();
            }
        }
    }

    (value, pos, false)
}

/// A `Clone`able `MakeTlsConnect` over a shared rustls [`ClientConfig`].
#[derive(Clone)]
pub(crate) struct MakeRustlsConnect {
    config: Arc<ClientConfig>,
}

impl MakeRustlsConnect {
    /// Build the connector for `mode`. For a verifying mode this loads the trust roots; for a
    /// non-verifying mode it installs a verifier that checks the handshake signature cryptographically
    /// but does not validate the certificate chain or identity (encrypt-only). For `disable` the
    /// connector is still built (harmlessly, as a non-verifying config) but is never invoked.
    fn build(mode: PgSslMode) -> Result<Self, StoreError> {
        let provider = crypto_provider();
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| StoreError::PgTls(format!("rustls protocol setup failed: {e}")))?;

        let config = if mode.verifies() {
            builder
                .with_root_certificates(load_roots()?)
                .with_no_client_auth()
        } else {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(EncryptOnlyVerifier::new(provider)))
                .with_no_client_auth()
        };

        Ok(Self {
            config: Arc::new(config),
        })
    }
}

impl MakeTlsConnect<Socket> for MakeRustlsConnect {
    type Stream = RustlsStream;
    type TlsConnect = RustlsConnect;
    type Error = TlsSetupError;

    fn make_tls_connect(&mut self, domain: &str) -> Result<RustlsConnect, TlsSetupError> {
        let server_name = ServerName::try_from(domain.to_owned())
            .map_err(|_| TlsSetupError(format!("invalid TLS server name {domain:?}")))?;
        Ok(RustlsConnect {
            connector: tokio_rustls::TlsConnector::from(self.config.clone()),
            server_name,
        })
    }
}

/// The per-connection connector produced by [`MakeRustlsConnect`].
pub(crate) struct RustlsConnect {
    connector: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
}

impl TlsConnect<Socket> for RustlsConnect {
    type Stream = RustlsStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<RustlsStream>> + Send>>;

    fn connect(self, stream: Socket) -> Self::Future {
        Box::pin(async move {
            let tls = self.connector.connect(self.server_name, stream).await?;
            Ok(RustlsStream(tls))
        })
    }
}

/// The TLS-wrapped socket handed back to tokio-postgres. A thin newtype over the tokio-rustls client
/// stream so we can attach the `TlsStream` channel-binding impl.
pub(crate) struct RustlsStream(tokio_rustls::client::TlsStream<Socket>);

impl AsyncRead for RustlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for RustlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

impl TlsStream for RustlsStream {
    fn channel_binding(&self) -> ChannelBinding {
        // SCRAM-PLUS channel binding is not negotiated; plain SCRAM over the encrypted channel is
        // used. See the module docs.
        ChannelBinding::none()
    }
}

/// A rustls verifier for the `require`/`prefer` modes: it validates the handshake signature with the
/// provider's algorithms (so the peer proves possession of the presented key), but does not check
/// the certificate chain, expiry, or hostname. The result is encryption without server
/// authentication — protection against passive eavesdropping, not an active MITM. `verify-full` uses
/// the standard webpki verifier instead.
#[derive(Debug)]
struct EncryptOnlyVerifier {
    provider: Arc<CryptoProvider>,
}

impl EncryptOnlyVerifier {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for EncryptOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The crypto provider used to build every rustls config. Reuses a process-installed default (e.g.
/// one already set by another workspace crate) so a single provider is used, else falls back to the
/// aws-lc-rs provider already compiled into the workspace. Using an explicit provider avoids the
/// "no process-level default CryptoProvider" panic path in `ClientConfig::builder()`.
fn crypto_provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

/// Load the trust roots for `verify-full`: the PEM file at [`ROOT_CERT_ENV`] if set, else the OS
/// trust store. Fails closed if no usable root certificate is found — `verify-full` must never
/// silently degrade to trusting nothing.
fn load_roots() -> Result<RootCertStore, StoreError> {
    let mut roots = RootCertStore::empty();

    match std::env::var(ROOT_CERT_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        Some(path) => {
            let pem = std::fs::read(&path).map_err(|e| {
                StoreError::PgTls(format!("reading {ROOT_CERT_ENV} file {path:?}: {e}"))
            })?;
            let mut added = 0usize;
            for cert in CertificateDer::pem_slice_iter(&pem) {
                let cert = cert
                    .map_err(|e| StoreError::PgTls(format!("parsing root CA PEM {path:?}: {e}")))?;
                roots
                    .add(cert)
                    .map_err(|e| StoreError::PgTls(format!("adding root CA from {path:?}: {e}")))?;
                added += 1;
            }
            if added == 0 {
                return Err(StoreError::PgTls(format!(
                    "no certificates found in {ROOT_CERT_ENV} file {path:?}"
                )));
            }
        }
        None => {
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                let _ = roots.add(cert);
            }
            if roots.is_empty() {
                return Err(StoreError::PgTls(format!(
                    "sslmode=verify-full requires trusted root CAs but the OS trust store yielded \
                     none; set {ROOT_CERT_ENV} to a PEM bundle"
                )));
            }
        }
    }

    Ok(roots)
}

/// Error raised while building a per-connection TLS connector (e.g. an invalid SNI host).
#[derive(Debug)]
pub(crate) struct TlsSetupError(String);

impl fmt::Display for TlsSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TlsSetupError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_sslmodes_and_rejects_unknown() {
        assert_eq!(PgSslMode::parse("disable"), Some(PgSslMode::Disable));
        assert_eq!(PgSslMode::parse("prefer"), Some(PgSslMode::Prefer));
        assert_eq!(PgSslMode::parse("require"), Some(PgSslMode::Require));
        assert_eq!(PgSslMode::parse("verify-full"), Some(PgSslMode::VerifyFull));
        // verify-ca is accepted and hardened to verify-full.
        assert_eq!(PgSslMode::parse("VERIFY-CA"), Some(PgSslMode::VerifyFull));
        assert_eq!(PgSslMode::parse("allow"), None);
        assert_eq!(PgSslMode::parse(""), None);
    }

    #[test]
    fn wire_mode_maps_verify_full_to_require() {
        assert_eq!(PgSslMode::Disable.wire_mode(), SslMode::Disable);
        assert_eq!(PgSslMode::Prefer.wire_mode(), SslMode::Prefer);
        assert_eq!(PgSslMode::Require.wire_mode(), SslMode::Require);
        assert_eq!(PgSslMode::VerifyFull.wire_mode(), SslMode::Require);
        assert!(PgSslMode::VerifyFull.verifies());
        assert!(!PgSslMode::Require.verifies());
    }

    #[test]
    fn strips_sslmode_from_url_query_and_captures_value() {
        let (mode, stripped) = extract_and_strip_sslmode(
            "postgres://u:p@host:5432/db?sslmode=verify-full&application_name=chancela",
        );
        assert_eq!(mode.as_deref(), Some("verify-full"));
        assert_eq!(
            stripped,
            "postgres://u:p@host:5432/db?application_name=chancela"
        );
    }

    #[test]
    fn strips_sslmode_when_it_is_the_only_query_param() {
        let (mode, stripped) = extract_and_strip_sslmode("postgres://u:p@host/db?sslmode=require");
        assert_eq!(mode.as_deref(), Some("require"));
        assert_eq!(stripped, "postgres://u:p@host/db");
    }

    #[test]
    fn leaves_url_without_sslmode_untouched() {
        let (mode, stripped) = extract_and_strip_sslmode("postgres://u:p@host:5432/db");
        assert_eq!(mode, None);
        assert_eq!(stripped, "postgres://u:p@host:5432/db");
    }

    #[test]
    fn treats_question_marks_in_keyword_form_as_part_of_values() {
        let (mode, stripped) =
            extract_and_strip_sslmode("host=db password='p?ss word' sslmode=prefer dbname=c");
        assert_eq!(mode.as_deref(), Some("prefer"));
        assert_eq!(stripped, "host=db password='p?ss word' dbname=c");
    }

    #[test]
    fn strips_sslmode_from_keyword_form() {
        let (mode, stripped) =
            extract_and_strip_sslmode("host=db.internal user=chancela sslmode=disable dbname=c");
        assert_eq!(mode.as_deref(), Some("disable"));
        assert_eq!(stripped, "host=db.internal user=chancela dbname=c");
    }

    #[test]
    fn strips_sslmode_from_keyword_form_without_corrupting_quoted_values() {
        let (mode, stripped) = extract_and_strip_sslmode(
            "host=db.internal application_name='Chancela API worker' sslmode=require \
             dbname='chan\\'cela'",
        );
        assert_eq!(mode.as_deref(), Some("require"));
        assert_eq!(
            stripped,
            "host=db.internal application_name='Chancela API worker' dbname='chan\\'cela'"
        );
    }

    #[test]
    fn strips_quoted_sslmode_from_keyword_form() {
        let (mode, stripped) =
            extract_and_strip_sslmode("host=db.internal sslmode='verify-full' dbname=chancela");
        assert_eq!(mode.as_deref(), Some("verify-full"));
        assert_eq!(stripped, "host=db.internal dbname=chancela");
    }

    #[test]
    fn rejects_insecure_effective_sslmodes() {
        for dsn in [
            "postgres://u:p@host/db?sslmode=disable",
            "postgres://u:p@host/db?sslmode=prefer",
            "postgres://u:p@host/db?sslmode=require",
        ] {
            let err = match resolve(dsn) {
                Ok(_) => panic!("insecure sslmode must fail closed: {dsn}"),
                Err(err) => err,
            };
            assert!(err.to_string().contains("sslmode must be verify-full"));
        }
    }

    #[test]
    fn missing_sslmode_defaults_to_verify_full() {
        match resolve("postgres://u:p@host:5432/db") {
            Ok(resolved) => assert_eq!(resolved.mode, PgSslMode::VerifyFull),
            Err(err) => assert!(
                err.to_string().contains("trusted root CAs")
                    || err.to_string().contains("invalid dns name")
            ),
        }
    }
}
