//! The crate error type ([`RegistryError`]).

/// Failure modes of a registry consultation.
///
/// `InvalidCode` messages MUST NOT echo the raw access code (mask or omit it) — the whole code is
/// a secret credential (LEG-22 / GDPR).
///
/// # Why the variants are this finely split
///
/// These are the sentences an operator is shown when a consultation fails, and collapsing them
/// lies. The two failures that matter most are opposites: **the code was wrong** (the operator's
/// input) and **the registry could not be reached** (nothing to do with their input). Reporting
/// one as the other either sends someone hunting a network fault over a typo, or — far worse —
/// implies a company has no registry record when in truth we never got an answer.
///
/// Three distinctions here are deliberate and worth stating:
///
/// - [`Config`](RegistryError::Config) is **our own** misconfiguration and is kept apart from every
///   upstream variant, so an operator is told their installation is at fault rather than being
///   pointed at a government service that is working fine.
/// - [`CodeRejected`](RegistryError::CodeRejected) does **not** claim "expired". The live
///   consultation page answers a bad code with *"O código de acesso introduzido não é válido ou a
///   certidão já expirou"* — the service itself refuses to say which. Splitting that into a
///   confident "expired" would invent a distinction the registry never made, so the variant carries
///   the disjunction honestly and the UI repeats it.
/// - [`CertidaoNotFound`](RegistryError::CertidaoNotFound) is a *different real page* ("Não existe
///   qualquer certidão com esse número"), not a synonym of the above, so it keeps its own variant.
///
/// Note that a rejected code arrives over **HTTP 200** — the consultation page reports it in the
/// body, not the status — so classification is a parse-level concern, not a transport one.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// The access code failed **our own** validation before any request was made (not 12 digits).
    /// Maps to `422` at the API.
    #[error("invalid access code: {0}")]
    InvalidCode(String),
    /// The registry answered, and rejected the code as invalid **or** expired — it does not
    /// distinguish the two, and neither do we. Maps to `422`: the input is at fault, not the
    /// service.
    #[error("the registry rejected the access code as invalid or expired: {0}")]
    CodeRejected(String),
    /// The registry answered that no certidão exists for that number. Maps to `422` — a definite
    /// answer from a working service, not an upstream failure.
    #[error("the registry has no certidão for that number: {0}")]
    CertidaoNotFound(String),
    /// The registry could not be reached at all (DNS, connect, TLS or timeout). Maps to `502`.
    /// **Never** implies anything about whether the company or certidão exists.
    #[error("could not reach the registry: {0}")]
    Unreachable(String),
    /// The registry refused our credentials (HTTP 401/403). Maps to `502`. Distinct from a rejected
    /// access code: this is the *consultation service* refusing us, not the code being wrong.
    #[error("the registry rejected our credentials: {0}")]
    CredentialsRejected(String),
    /// The registry applied a rate limit or quota (HTTP 429). Maps to `502`. Retryable, unlike
    /// every other upstream failure.
    #[error("the registry rate-limited or refused further consultations for now: {0}")]
    QuotaExceeded(String),
    /// Any other HTTP/empty-body failure consulting the registry. Maps to `502`.
    #[error("registry upstream failure: {0}")]
    Upstream(String),
    /// The response was `200` but was not a recognisable certidão, and not one of the registry's
    /// known error pages either. Maps to `502` — we genuinely do not know what we received, and say
    /// so rather than guessing that the code was bad.
    #[error("response was not a recognisable certidão: {0}")]
    Unrecognized(String),
    /// Misconfiguration on **our** side (bad base URL, missing required env). Maps to `500`.
    #[error("config error: {0}")]
    Config(String),
}

impl RegistryError {
    /// A stable, machine-readable identifier for this failure.
    ///
    /// English, and it stays English: this is an identifier the web client maps to pt-PT copy, not
    /// copy itself (mirrors `ApiError::code`). The `registry.` prefix keeps these from colliding
    /// with the bare domain-code vocabularies already on this wire.
    pub fn code(&self) -> &'static str {
        match self {
            RegistryError::InvalidCode(_) => "registry.invalid_code",
            RegistryError::CodeRejected(_) => "registry.code_rejected",
            RegistryError::CertidaoNotFound(_) => "registry.certidao_not_found",
            RegistryError::Unreachable(_) => "registry.unreachable",
            RegistryError::CredentialsRejected(_) => "registry.credentials_rejected",
            RegistryError::QuotaExceeded(_) => "registry.quota_exceeded",
            RegistryError::Upstream(_) => "registry.upstream",
            RegistryError::Unrecognized(_) => "registry.unrecognized",
            RegistryError::Config(_) => "registry.config",
        }
    }
}
