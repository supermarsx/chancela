//! Priority-ordered credential resolution + failover driver for the signing paths (wp13 Phase C).
//!
//! This module is the credential-selection *engine* that sits between the Phase A store
//! ([`crate::secretstore_persist`]) and the signing paths in [`crate::signature`]. It is
//! deliberately decoupled from the (very large) `signature.rs`: it owns the two behaviours that are
//! easy to get subtly wrong and must be unit-tested in isolation —
//!
//! 1. **Candidate resolution** ([`resolve_candidates`]): read a provider's *enabled* stored entries
//!    in priority order and map each into a caller-chosen per-mode config `C`
//!    (`CmdConfig` / `CscConfig`+`CscSecrets` / `AmaScapConfig` / a [`Pkcs12SignerInput`]). When the
//!    provider has **no stored entries at all**, fall back to the single env-derived config — so the
//!    precedence is *stored-overrides-env, env-only when nothing is stored* (plan §2). If entries
//!    exist but are all disabled, env is **not** consulted (stored is the source of truth).
//!
//! 2. **Failover** ([`try_in_order`]): try candidates in priority order. On a **retryable** error
//!    (network / TLS / timeout, HTTP 5xx/429, unreachable endpoint) advance to the next candidate; on
//!    a **terminal** error (auth 401/403, wrong-PIN / bad-SAD / OTP-rejected 422, definitive provider
//!    refusal) **stop immediately** and surface it — never fail over past a real "no", which would
//!    burn the signer's remaining PIN/OTP attempts across every stored key. Genuinely-unknown error
//!    classes default to **terminal** (the safe default; see [`ClassifyError`]).
//!
//! Live transports are untouched: this module never makes an outbound call. The failover loop wraps
//! whatever `attempt` closure the caller passes, which is where the existing DI transport seams
//! (`state.cmd_transport` / `state.csc_transport`) are invoked.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroizing;

use chancela_cmd::CmdError;
use chancela_csc::CscError;
use chancela_scap::ScapError;
use chancela_signing::{Pkcs12IdentitySelector, SoftCertificateError};

use crate::secretstore_persist::{
    CredentialMode, DecryptedCredentialEntry, FIELD_PKCS12_PASSPHRASE, FIELD_PKCS12_PFX,
    ProviderCredentialError, ProviderCredentialStore,
};

// --- Error classification ------------------------------------------------------------------

/// Whether a failed signing attempt may be retried against the **next** credential candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// The key/endpoint could not be reached or the provider transiently failed — advancing to the
    /// next candidate is safe (it does not consume a signer decision). Network/TLS/timeout,
    /// unreachable/misconfigured endpoint, HTTP 5xx, HTTP 429.
    Retryable,
    /// A definitive decision was reached — auth-invalid, wrong-PIN / bad-SAD / OTP-rejected,
    /// credential-not-authorized, an explicit refusal, or an *unknown* failure. Failing over here
    /// would either burn the signer's remaining attempts or mask a real "no", so we stop.
    Terminal,
}

/// Maps a transport/signing error onto a [`ErrorClass`] for the failover driver. The **safe default
/// for anything ambiguous is [`ErrorClass::Terminal`]** — we never keep trying keys on an error we do
/// not positively recognise as a transient "could not reach", because that risks burning PIN/OTP
/// attempts across a signer's keys.
pub trait ClassifyError {
    /// Classify `self` as retryable (advance to the next candidate) or terminal (stop now).
    fn error_class(&self) -> ErrorClass;
}

/// `true` for the HTTP status codes that indicate a transient/server-side condition worth failing
/// over on (server errors + rate limiting). Everything else — notably 401/403/404/422 — is a
/// definitive answer and is treated as terminal.
fn http_status_is_retryable(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

impl ClassifyError for CmdError {
    fn error_class(&self) -> ErrorClass {
        match self {
            // Transport covers connection/TLS/timeout and non-fault HTTP error statuses — the
            // "could not reach this endpoint" bucket.
            CmdError::Transport(_) => ErrorClass::Retryable,
            // A misbehaving/hostile endpoint returned an oversized body: treat as a bad endpoint and
            // try the next candidate rather than trusting it.
            CmdError::ResponseTooLarge { .. } => ErrorClass::Retryable,
            // OTP rejection is the possession-factor "no" — failing over would burn the next key's
            // attempts. A SOAP fault / non-success service status is a definitive provider decision.
            CmdError::OtpRejected { .. }
            | CmdError::SoapFault(_)
            | CmdError::ServiceStatus { .. }
            | CmdError::Config(_)
            | CmdError::Encryption(_)
            | CmdError::Certificate(_)
            | CmdError::RequestBuild(_)
            | CmdError::ResponseParse(_)
            | CmdError::Base64(_) => ErrorClass::Terminal,
            // #[non_exhaustive]: default unknown to terminal.
            _ => ErrorClass::Terminal,
        }
    }
}

impl ClassifyError for CscError {
    fn error_class(&self) -> ErrorClass {
        match self {
            CscError::Transport(_) => ErrorClass::Retryable,
            CscError::ResponseTooLarge { .. } => ErrorClass::Retryable,
            // Only server-side / rate-limit statuses are retryable; 401/403/404/422 are definitive.
            CscError::HttpStatus { status } if http_status_is_retryable(*status) => {
                ErrorClass::Retryable
            }
            CscError::HttpStatus { .. } => ErrorClass::Terminal,
            // A structured CSC error body (`invalid_otp`, `invalid_request`, …) is a provider "no";
            // `invalid_otp`/SAD rejection must NOT fail over. NoCredential / NoSignature / parse /
            // config / certificate / base64 are all definitive.
            CscError::Service { .. }
            | CscError::ResponseParse(_)
            | CscError::Config(_)
            | CscError::NoCredential { .. }
            | CscError::NoSignature
            | CscError::Certificate(_)
            | CscError::Base64(_) => ErrorClass::Terminal,
            _ => ErrorClass::Terminal,
        }
    }
}

impl ClassifyError for ScapError {
    fn error_class(&self) -> ErrorClass {
        match self {
            // The only "could not reach" bucket for SCAP.
            ScapError::Transport(_) => ErrorClass::Retryable,
            // Config / attribute-not-granted / assembly failures are definitive.
            ScapError::Config(_) | ScapError::Verification(_) | ScapError::Signature(_) => {
                ErrorClass::Terminal
            }
            _ => ErrorClass::Terminal,
        }
    }
}

impl ClassifyError for SoftCertificateError {
    fn error_class(&self) -> ErrorClass {
        // Local PKCS#12 loading never touches the network: every failure is definitive. In
        // particular a wrong passphrase must never trigger a fail-over onto another stored identity.
        match self {
            SoftCertificateError::WrongPassword
            | SoftCertificateError::MissingPrivateKey
            | SoftCertificateError::UnsupportedKeyAlgorithm { .. }
            | SoftCertificateError::EmptyCertificateChain
            | SoftCertificateError::MalformedInput(_) => ErrorClass::Terminal,
            _ => ErrorClass::Terminal,
        }
    }
}

// --- Resolved candidates -------------------------------------------------------------------

/// Where a resolved candidate's material came from (non-secret; safe for the audit/attempt trail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedSource {
    /// A stored entry, identified by its (non-secret) id and label.
    Stored {
        /// The stored entry id.
        entry_id: String,
        /// The stored entry's operator-facing label.
        label: String,
    },
    /// The environment/DI fallback used when the provider has no stored entries.
    Env,
}

/// One resolved credential candidate: its assembled per-mode config `C` plus non-secret provenance.
/// Candidates are yielded in the order they should be attempted (stored entries in ascending
/// priority, or the single env fallback).
pub struct ResolvedCredential<C> {
    /// Non-secret provenance of this candidate.
    pub source: ResolvedSource,
    /// The assembled per-mode config/secret bundle (`CmdConfig`, `CscSecrets`, `AmaScapConfig`,
    /// [`Pkcs12SignerInput`], …). Secret material inside `C` stays in its own `Zeroizing` buffers.
    pub config: C,
}

/// Failure to resolve the candidate list.
#[derive(Debug)]
pub enum ResolveError<E> {
    /// The store failed (corrupt sidecar, no key source, AEAD auth failure, …).
    Store(ProviderCredentialError),
    /// A candidate's secret fields could not be assembled into the per-mode config (e.g. an
    /// incomplete stored entry, or a malformed env config).
    Assemble(E),
}

impl<E: std::fmt::Display> std::fmt::Display for ResolveError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Store(e) => write!(f, "{e}"),
            ResolveError::Assemble(e) => write!(f, "{e}"),
        }
    }
}

/// Resolve the ordered credential candidate list for `(mode, provider_id)` (plan §2).
///
/// - Reads the provider's stored entries (already priority-sorted by
///   [`ProviderCredentialStore::read_entries`]), keeps only the **enabled** ones, and maps each into
///   a per-mode config `C` via `assemble_stored`, preserving priority order.
/// - When the provider has **no stored entries at all**, calls `env_fallback` and, if it yields
///   `Some(config)`, returns it as the single [`ResolvedSource::Env`] candidate. If entries exist but
///   are all disabled, the env fallback is **not** consulted (stored is authoritative) and an empty
///   list is returned — the caller then fails closed via the existing PROD validators.
///
/// `assemble_stored` decrypts/maps one entry's already-decrypted fields; propagating its error fails
/// closed (matching the existing single-entry behaviour) rather than silently skipping a
/// misconfigured entry.
pub fn resolve_candidates<C, E>(
    store: &ProviderCredentialStore,
    mode: CredentialMode,
    provider_id: &str,
    mut assemble_stored: impl FnMut(&DecryptedCredentialEntry) -> Result<C, E>,
    env_fallback: impl FnOnce() -> Result<Option<C>, E>,
) -> Result<Vec<ResolvedCredential<C>>, ResolveError<E>> {
    // Runtime signing read: apply the strict-mode protection guard so stored-credential signing
    // refuses when strict storage is on but protection has degraded below confidential at runtime
    // (mirrors the flat `read_runtime` path; see `secretstore_persist::read_entries_runtime`).
    let entries = store
        .read_entries_runtime(mode, provider_id)
        .map_err(ResolveError::Store)?;

    if entries.is_empty() {
        // Whole-provider fallback: env is consulted only when nothing at all is stored (plan §2).
        return match env_fallback().map_err(ResolveError::Assemble)? {
            Some(config) => Ok(vec![ResolvedCredential {
                source: ResolvedSource::Env,
                config,
            }]),
            None => Ok(Vec::new()),
        };
    }

    // Stored entries exist → env is never consulted for this provider. Attempt enabled entries in
    // priority order (read_entries already sorts ascending by (priority, id)).
    let mut candidates = Vec::new();
    for entry in entries.iter().filter(|e| e.enabled) {
        let config = assemble_stored(entry).map_err(ResolveError::Assemble)?;
        candidates.push(ResolvedCredential {
            source: ResolvedSource::Stored {
                entry_id: entry.entry_id.clone(),
                label: entry.label.clone(),
            },
            config,
        });
    }
    Ok(candidates)
}

// --- Failover driver -----------------------------------------------------------------------

/// The outcome of running [`try_in_order`] to exhaustion without a success.
#[derive(Debug)]
pub enum FailoverError<E> {
    /// A candidate returned a **terminal** error: we stopped immediately and did **not** try any
    /// later candidate. Carries the terminal error to surface to the caller.
    Terminal(E),
    /// Every candidate was tried and all failed **retryably**. Carries the last error seen.
    Exhausted(E),
    /// The candidate list was empty (nothing stored and no env fallback) — the caller must fail
    /// closed through the existing PROD validators.
    NoCandidates,
}

impl<E: std::fmt::Display> std::fmt::Display for FailoverError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailoverError::Terminal(e) => write!(f, "{e}"),
            FailoverError::Exhausted(e) => write!(f, "{e}"),
            FailoverError::NoCandidates => {
                write!(f, "no credential candidates were available")
            }
        }
    }
}

/// Try `attempt` against each candidate in order, applying the retryable/terminal policy (plan §2).
///
/// - On `Ok(value)` — return it.
/// - On a **retryable** error — remember it and advance to the next candidate.
/// - On a **terminal** error — return [`FailoverError::Terminal`] **immediately**, without touching
///   any later candidate (this is what prevents a wrong-PIN/OTP from burning attempts across keys).
///
/// If every candidate fails retryably, returns [`FailoverError::Exhausted`] with the last error; an
/// empty candidate slice returns [`FailoverError::NoCandidates`].
pub fn try_in_order<C, T, E, F>(
    candidates: &[ResolvedCredential<C>],
    mut attempt: F,
) -> Result<T, FailoverError<E>>
where
    F: FnMut(&ResolvedCredential<C>) -> Result<T, E>,
    E: ClassifyError,
{
    let mut last_retryable = None;
    for candidate in candidates {
        match attempt(candidate) {
            Ok(value) => return Ok(value),
            Err(err) => match err.error_class() {
                ErrorClass::Terminal => return Err(FailoverError::Terminal(err)),
                ErrorClass::Retryable => last_retryable = Some(err),
            },
        }
    }
    match last_retryable {
        Some(err) => Err(FailoverError::Exhausted(err)),
        None => Err(FailoverError::NoCandidates),
    }
}

/// The **async** twin of [`try_in_order`], for signing paths whose per-candidate attempt is an
/// `async fn` (the CMD/CSC two-phase remote initiate runs the real provider call on `spawn_blocking`
/// and must be `.await`ed). The retryable/terminal policy is byte-identical to [`try_in_order`]:
///
/// - `Ok(value)` — return it.
/// - a **retryable** error — remember it and advance to the next candidate.
/// - a **terminal** error — return [`FailoverError::Terminal`] **immediately**, without touching any
///   later candidate (the OTP/PIN-burn guard: a real provider "no" must never cascade to — and burn —
///   the next stored credential's attempts).
///
/// An empty slice returns [`FailoverError::NoCandidates`]; all-retryable returns
/// [`FailoverError::Exhausted`] with the last error.
pub async fn try_in_order_async<C, T, E, F, Fut>(
    candidates: &[ResolvedCredential<C>],
    mut attempt: F,
) -> Result<T, FailoverError<E>>
where
    F: FnMut(&ResolvedCredential<C>) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: ClassifyError,
{
    let mut last_retryable = None;
    for candidate in candidates {
        match attempt(candidate).await {
            Ok(value) => return Ok(value),
            Err(err) => match err.error_class() {
                ErrorClass::Terminal => return Err(FailoverError::Terminal(err)),
                ErrorClass::Retryable => last_retryable = Some(err),
            },
        }
    }
    match last_retryable {
        Some(err) => Err(FailoverError::Exhausted(err)),
        None => Err(FailoverError::NoCandidates),
    }
}

// --- PKCS#12 signer input (the one genuinely-new per-mode assembly) -------------------------

/// Selector key: the PKCS#12 `friendlyName` to match when a PFX carries several identities.
pub const SELECTOR_PKCS12_FRIENDLY_NAME: &str = "friendly_name";
/// Selector key: the PKCS#12 `localKeyId`, hex-encoded, to match a specific identity.
pub const SELECTOR_PKCS12_LOCAL_KEY_ID_HEX: &str = "local_key_id_hex";

/// A stored PKCS#12 identity assembled into the inputs [`chancela_signing::Pkcs12SigningSource`]
/// needs. The PFX bytes and passphrase are kept only in [`Zeroizing`] buffers so they are wiped on
/// drop; nothing here is ever logged or serialised.
pub struct Pkcs12SignerInput {
    /// The raw PKCS#12/PFX DER bytes (base64-decoded from the stored `pfx_der` field).
    pub pfx_der: Zeroizing<Vec<u8>>,
    /// The PKCS#12 passphrase.
    pub passphrase: Zeroizing<String>,
    /// Which identity to select from the PFX (from the entry's non-secret selectors).
    pub selector: Pkcs12IdentitySelector,
}

impl std::fmt::Debug for Pkcs12SignerInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs12SignerInput")
            .field("pfx_der", &"<redacted>")
            .field("passphrase", &"<redacted>")
            .field("selector", &self.selector)
            .finish()
    }
}

/// Why a stored PKCS#12 entry could not be assembled into a [`Pkcs12SignerInput`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkcs12AssembleError {
    /// A required secret field (`pfx_der` / `passphrase`) was absent or blank.
    MissingField(&'static str),
    /// The stored `pfx_der` field was not valid base64.
    MalformedPfxEncoding,
    /// A `local_key_id_hex` selector was present but not valid hex.
    MalformedLocalKeyId,
}

impl std::fmt::Display for Pkcs12AssembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pkcs12AssembleError::MissingField(field) => {
                write!(f, "stored PKCS#12 entry is missing the {field:?} field")
            }
            Pkcs12AssembleError::MalformedPfxEncoding => {
                write!(f, "stored PKCS#12 PFX field is not valid base64")
            }
            Pkcs12AssembleError::MalformedLocalKeyId => {
                write!(
                    f,
                    "stored PKCS#12 local_key_id_hex selector is not valid hex"
                )
            }
        }
    }
}

impl std::error::Error for Pkcs12AssembleError {}

/// Build the [`Pkcs12IdentitySelector`] a stored entry's non-secret selectors describe. An entry with
/// no selectors matches any single identity in the PFX.
fn pkcs12_selector_from_entry(
    entry: &DecryptedCredentialEntry,
) -> Result<Pkcs12IdentitySelector, Pkcs12AssembleError> {
    let friendly_name = entry
        .selectors
        .get(SELECTOR_PKCS12_FRIENDLY_NAME)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let local_key_id = match entry
        .selectors
        .get(SELECTOR_PKCS12_LOCAL_KEY_ID_HEX)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(hex) => Some(decode_hex(hex).ok_or(Pkcs12AssembleError::MalformedLocalKeyId)?),
        None => None,
    };
    let mut selector = Pkcs12IdentitySelector::any();
    selector.friendly_name = friendly_name;
    selector.local_key_id = local_key_id;
    Ok(selector)
}

/// Assemble a stored PKCS#12 entry's decrypted fields into a [`Pkcs12SignerInput`] (base64-decode the
/// PFX, take the passphrase, and read the identity selector from the entry's non-secret selectors).
pub fn assemble_pkcs12_input(
    entry: &DecryptedCredentialEntry,
) -> Result<Pkcs12SignerInput, Pkcs12AssembleError> {
    let pfx_b64 = entry
        .fields
        .get(FIELD_PKCS12_PFX)
        .filter(|v| !v.trim().is_empty())
        .ok_or(Pkcs12AssembleError::MissingField(FIELD_PKCS12_PFX))?;
    let passphrase = entry
        .fields
        .get(FIELD_PKCS12_PASSPHRASE)
        .filter(|v| !v.is_empty())
        .ok_or(Pkcs12AssembleError::MissingField(FIELD_PKCS12_PASSPHRASE))?;
    let pfx_der = Zeroizing::new(
        B64.decode(pfx_b64.as_bytes())
            .map_err(|_| Pkcs12AssembleError::MalformedPfxEncoding)?,
    );
    let selector = pkcs12_selector_from_entry(entry)?;
    Ok(Pkcs12SignerInput {
        pfx_der,
        passphrase: Zeroizing::new(passphrase.as_str().to_owned()),
        selector,
    })
}

/// Decode a lower/upper-case hex string into bytes, or `None` if it is malformed (odd length or a
/// non-hex digit).
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::secretstore_persist::{
        CredentialFieldSet, CscCredentialFields, EntryMetadata, EntrySelectors,
        Pkcs12CredentialFields,
    };

    // --- test scaffolding ------------------------------------------------------------------

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    const TEST_DB_KEY: &[u8] = b"wp13-phase-c-unit-test-db-key-01234";

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(name: &str) -> Self {
            let seq = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "chancela-credresolve-{name}-{}-{seq}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn store(dir: &Path) -> ProviderCredentialStore {
        ProviderCredentialStore::load_with_db_key(dir, TEST_DB_KEY, false)
    }

    fn z(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    fn meta(priority: i32, enabled: bool) -> EntryMetadata {
        EntryMetadata {
            label: format!("entry-p{priority}"),
            priority,
            enabled,
            endpoint: None,
            selectors: EntrySelectors::new(),
        }
    }

    /// A trivial per-mode config for the ordering/failover tests: just the client-secret string that
    /// was stored, so a test can assert which candidate was assembled.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct StubConfig(String);

    fn assemble_stub(entry: &DecryptedCredentialEntry) -> Result<StubConfig, String> {
        Ok(StubConfig(
            entry
                .fields
                .get("client_secret")
                .map(|z| z.as_str().to_owned())
                .unwrap_or_default(),
        ))
    }

    // --- resolve_candidates: priority ordering ---------------------------------------------

    #[test]
    fn candidates_are_returned_in_priority_order() {
        let dir = TempDir::new("priority");
        let store = store(dir.path());
        // Insert out of order: high-priority number first.
        for (id, priority, secret) in [
            ("z-entry", 5, "secret-five"),
            ("a-entry", 1, "secret-one"),
            ("m-entry", 3, "secret-three"),
        ] {
            store
                .put_entry(
                    CredentialMode::CscQtsp,
                    "prov",
                    id,
                    Some(meta(priority, true)),
                    CscCredentialFields {
                        client_secret: Some(z(secret)),
                        ..Default::default()
                    }
                    .into_set_pairs(),
                    &[],
                )
                .expect("put");
        }

        let candidates = resolve_candidates(
            &store,
            CredentialMode::CscQtsp,
            "prov",
            assemble_stub,
            || Ok::<_, String>(None),
        )
        .expect("resolve");

        let order: Vec<&str> = candidates.iter().map(|c| c.config.0.as_str()).collect();
        assert_eq!(order, ["secret-one", "secret-three", "secret-five"]);
        // All are tagged as stored, never env.
        assert!(
            candidates
                .iter()
                .all(|c| matches!(c.source, ResolvedSource::Stored { .. }))
        );
    }

    #[test]
    fn disabled_entries_are_skipped_and_do_not_trigger_env() {
        let dir = TempDir::new("disabled");
        let store = store(dir.path());
        store
            .put_entry(
                CredentialMode::CscQtsp,
                "prov",
                "enabled",
                Some(meta(1, true)),
                CscCredentialFields {
                    client_secret: Some(z("live")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put enabled");
        store
            .put_entry(
                CredentialMode::CscQtsp,
                "prov",
                "disabled",
                Some(meta(0, false)),
                CscCredentialFields {
                    client_secret: Some(z("dormant")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put disabled");

        let mut env_called = false;
        let candidates = resolve_candidates(
            &store,
            CredentialMode::CscQtsp,
            "prov",
            assemble_stub,
            || {
                env_called = true;
                Ok::<_, String>(Some(StubConfig("env".to_owned())))
            },
        )
        .expect("resolve");

        // The disabled (priority 0) entry is skipped; the enabled one is the only candidate; env is
        // NOT consulted because stored entries exist.
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].config.0, "live");
        assert!(
            !env_called,
            "env must not be consulted when entries are stored"
        );
    }

    // --- resolve_candidates: env fallback --------------------------------------------------

    #[test]
    fn env_fallback_when_store_is_empty() {
        let dir = TempDir::new("env-empty");
        let store = store(dir.path());

        let candidates = resolve_candidates(
            &store,
            CredentialMode::CscQtsp,
            "unconfigured",
            assemble_stub,
            || Ok::<_, String>(Some(StubConfig("env-secret".to_owned()))),
        )
        .expect("resolve");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].source, ResolvedSource::Env);
        assert_eq!(candidates[0].config.0, "env-secret");
    }

    #[test]
    fn empty_store_and_no_env_yields_no_candidates() {
        let dir = TempDir::new("env-none");
        let store = store(dir.path());

        let candidates = resolve_candidates(
            &store,
            CredentialMode::CscQtsp,
            "unconfigured",
            assemble_stub,
            || Ok::<_, String>(None),
        )
        .expect("resolve");

        assert!(candidates.is_empty());
    }

    #[test]
    fn stored_overrides_env_when_both_exist() {
        let dir = TempDir::new("stored-wins");
        let store = store(dir.path());
        store
            .put_entry(
                CredentialMode::CscQtsp,
                "prov",
                "primary",
                Some(meta(0, true)),
                CscCredentialFields {
                    client_secret: Some(z("stored-secret")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put");

        let mut env_called = false;
        let candidates = resolve_candidates(
            &store,
            CredentialMode::CscQtsp,
            "prov",
            assemble_stub,
            || {
                env_called = true;
                Ok::<_, String>(Some(StubConfig("env-secret".to_owned())))
            },
        )
        .expect("resolve");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].config.0, "stored-secret");
        assert!(matches!(
            candidates[0].source,
            ResolvedSource::Stored { .. }
        ));
        assert!(
            !env_called,
            "env fallback must not run when a stored entry exists"
        );
    }

    // --- try_in_order: failover policy -----------------------------------------------------

    fn stub_candidates(secrets: &[&str]) -> Vec<ResolvedCredential<StubConfig>> {
        secrets
            .iter()
            .enumerate()
            .map(|(i, s)| ResolvedCredential {
                source: ResolvedSource::Stored {
                    entry_id: format!("e{i}"),
                    label: String::new(),
                },
                config: StubConfig((*s).to_owned()),
            })
            .collect()
    }

    #[test]
    fn failover_advances_on_retryable_until_success() {
        let candidates = stub_candidates(&["first", "second", "third"]);
        let mut attempted = Vec::new();
        let out: Result<&str, FailoverError<CscError>> = try_in_order(&candidates, |c| {
            attempted.push(c.config.0.clone());
            if c.config.0 == "third" {
                Ok("signed")
            } else {
                // A transport failure is retryable → advance.
                Err(CscError::Transport("connection refused".to_owned()))
            }
        });

        assert_eq!(out.expect("signed"), "signed");
        assert_eq!(attempted, ["first", "second", "third"]);
    }

    #[test]
    fn failover_stops_on_terminal_and_does_not_burn_later_candidates() {
        // Two candidates: the first returns a wrong-OTP (terminal). The failover MUST stop and never
        // touch the second candidate — otherwise the signer's next key would burn an OTP/PIN attempt.
        let candidates = stub_candidates(&["first-key", "second-key"]);
        let mut attempted = Vec::new();
        let out: Result<&str, FailoverError<CmdError>> = try_in_order(&candidates, |c| {
            attempted.push(c.config.0.clone());
            Err(CmdError::OtpRejected {
                code: "422".to_owned(),
                message: "wrong OTP".to_owned(),
            })
        });

        match out {
            Err(FailoverError::Terminal(CmdError::OtpRejected { .. })) => {}
            other => panic!("expected terminal OtpRejected, got {other:?}"),
        }
        assert_eq!(
            attempted,
            ["first-key"],
            "only the first candidate may be attempted on a terminal error"
        );
    }

    #[test]
    fn failover_exhaustion_returns_last_retryable_error() {
        let candidates = stub_candidates(&["a", "b"]);
        let out: Result<&str, FailoverError<CscError>> =
            try_in_order(&candidates, |_| Err(CscError::HttpStatus { status: 503 }));
        match out {
            Err(FailoverError::Exhausted(CscError::HttpStatus { status: 503 })) => {}
            other => panic!("expected exhausted 503, got {other:?}"),
        }
    }

    #[test]
    fn failover_empty_candidates_is_no_candidates() {
        let candidates: Vec<ResolvedCredential<StubConfig>> = Vec::new();
        let out: Result<&str, FailoverError<CscError>> =
            try_in_order(&candidates, |_| Ok("unreachable"));
        assert!(matches!(out, Err(FailoverError::NoCandidates)));
    }

    // --- error classification --------------------------------------------------------------

    #[test]
    fn cmd_error_classification() {
        assert_eq!(
            CmdError::Transport("tls".into()).error_class(),
            ErrorClass::Retryable
        );
        assert_eq!(
            CmdError::OtpRejected {
                code: "1".into(),
                message: "x".into()
            }
            .error_class(),
            ErrorClass::Terminal
        );
        assert_eq!(
            CmdError::SoapFault("bad app id".into()).error_class(),
            ErrorClass::Terminal
        );
        assert_eq!(
            CmdError::Config("missing".into()).error_class(),
            ErrorClass::Terminal
        );
    }

    #[test]
    fn csc_error_classification_by_http_status() {
        assert_eq!(
            CscError::Transport("dns".into()).error_class(),
            ErrorClass::Retryable
        );
        assert_eq!(
            CscError::HttpStatus { status: 503 }.error_class(),
            ErrorClass::Retryable
        );
        assert_eq!(
            CscError::HttpStatus { status: 429 }.error_class(),
            ErrorClass::Retryable
        );
        // A definitive auth answer must NOT fail over.
        assert_eq!(
            CscError::HttpStatus { status: 401 }.error_class(),
            ErrorClass::Terminal
        );
        assert_eq!(
            CscError::HttpStatus { status: 422 }.error_class(),
            ErrorClass::Terminal
        );
        // invalid_otp / SAD rejection surfaces as a structured Service error → terminal.
        assert_eq!(
            CscError::Service {
                error: "invalid_otp".into(),
                description: "bad SAD".into()
            }
            .error_class(),
            ErrorClass::Terminal
        );
    }

    #[test]
    fn scap_and_softcert_classification() {
        assert_eq!(
            ScapError::Transport("timeout".into()).error_class(),
            ErrorClass::Retryable
        );
        assert_eq!(
            ScapError::Verification("not granted".into()).error_class(),
            ErrorClass::Terminal
        );
        // Every local PKCS#12 failure is terminal — a wrong passphrase must never fail over.
        assert_eq!(
            SoftCertificateError::WrongPassword.error_class(),
            ErrorClass::Terminal
        );
        assert_eq!(
            SoftCertificateError::MalformedInput("bad".into()).error_class(),
            ErrorClass::Terminal
        );
    }

    // --- PKCS#12 assembly ------------------------------------------------------------------

    #[test]
    fn pkcs12_input_round_trips_through_the_store() {
        let dir = TempDir::new("pkcs12");
        let store = store(dir.path());
        let pfx_bytes: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02];
        let pfx_b64 = B64.encode(pfx_bytes);

        let mut selectors = BTreeMap::new();
        selectors.insert(
            SELECTOR_PKCS12_FRIENDLY_NAME.to_owned(),
            "Amélia".to_owned(),
        );
        selectors.insert(
            SELECTOR_PKCS12_LOCAL_KEY_ID_HEX.to_owned(),
            "a1b2".to_owned(),
        );

        store
            .put_entry(
                CredentialMode::LocalPkcs12,
                "amelia-id",
                "e1",
                Some(EntryMetadata {
                    label: "Amélia".to_owned(),
                    priority: 0,
                    enabled: true,
                    endpoint: None,
                    selectors,
                }),
                Pkcs12CredentialFields {
                    pfx_der_b64: Some(z(&pfx_b64)),
                    passphrase: Some(z("s3nha")),
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put pkcs12");

        let candidates = resolve_candidates(
            &store,
            CredentialMode::LocalPkcs12,
            "amelia-id",
            assemble_pkcs12_input,
            || Ok::<_, Pkcs12AssembleError>(None),
        )
        .expect("resolve");

        assert_eq!(candidates.len(), 1);
        let input = &candidates[0].config;
        assert_eq!(input.pfx_der.as_slice(), pfx_bytes);
        assert_eq!(input.passphrase.as_str(), "s3nha");
        assert_eq!(input.selector.friendly_name.as_deref(), Some("Amélia"));
        assert_eq!(
            input.selector.local_key_id.as_deref(),
            Some(&[0xA1u8, 0xB2][..])
        );
    }

    #[test]
    fn pkcs12_assembly_rejects_missing_passphrase() {
        let entry = DecryptedCredentialEntry {
            entry_id: "e".into(),
            label: String::new(),
            priority: 0,
            enabled: true,
            endpoint: None,
            selectors: EntrySelectors::new(),
            fields: {
                let mut f = BTreeMap::new();
                f.insert(FIELD_PKCS12_PFX.to_owned(), z(&B64.encode([1u8, 2, 3])));
                f
            },
        };
        assert_eq!(
            assemble_pkcs12_input(&entry).unwrap_err(),
            Pkcs12AssembleError::MissingField(FIELD_PKCS12_PASSPHRASE)
        );
    }

    #[test]
    fn pkcs12_assembly_rejects_malformed_base64() {
        let entry = DecryptedCredentialEntry {
            entry_id: "e".into(),
            label: String::new(),
            priority: 0,
            enabled: true,
            endpoint: None,
            selectors: EntrySelectors::new(),
            fields: {
                let mut f = BTreeMap::new();
                f.insert(FIELD_PKCS12_PFX.to_owned(), z("not base64 !!!"));
                f.insert(FIELD_PKCS12_PASSPHRASE.to_owned(), z("pw"));
                f
            },
        };
        assert_eq!(
            assemble_pkcs12_input(&entry).unwrap_err(),
            Pkcs12AssembleError::MalformedPfxEncoding
        );
    }
}
