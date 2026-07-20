//! [`RemoteSigningSource`] — the two-phase, resumable seam every **remote** qualified-signing
//! provider plugs into (t59 Slice 1, F1).
//!
//! A remote QES is inherently multi-step: the signature spans two stateless requests with an
//! out-of-band activation step in between (Chave Móvel Digital dispatches an SMS OTP; a CSC-standard
//! QTSP dispatches an OTP or requires Signature Activation Data). This does not fit the synchronous
//! [`SignerProvider`](crate::SignerProvider) — whose one call must produce the signature — the way
//! Cartão de Cidadão does (its PIN is entered *at the reader* inside the single call). So remote
//! sources implement this trait instead:
//!
//! - [`RemoteSigningSource::initiate`] — authenticate, resolve the signer certificate (+chain for
//!   the trusted-list gate), gate it (SIG-11/23), take the PAdES prepared ByteRange digest, and open
//!   a provider-side signing session (dispatching an activation). Returns a [`RemoteSignSession`],
//!   a **secret-free**, serde-persistable handle the api stores between the two requests.
//! - [`RemoteSigningSource::confirm`] — given that session + the signer's transient completion
//!   credential (OTP / SAD), return the detached CAdES-B CMS ready for
//!   [`chancela_pades::embed_signature`].
//!
//! Chave Móvel Digital ([`CmdRemoteSource`](crate::cmd_session::CmdRemoteSource)) is the reference
//! implementation; a CSC-v2 QTSP adapter (`chancela-csc`, t59 Slice 2) implements the same trait, so
//! an api layer can hold `dyn RemoteSigningSource` and drive initiate/confirm uniformly across every
//! remote provider. Cartão de Cidadão is **not** a `RemoteSigningSource` — it stays on the
//! synchronous [`SignerProvider`] path (see `chancela_signing::cc`).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use chancela_pades::PreparedSignature;

use crate::policy::TrustPolicy;
use crate::{EvidentiaryLevel, SigningError, SigningFamily, TrustedListStatus};

/// The transient inputs to [`RemoteSigningSource::initiate`].
///
/// `credential` is a secret knowledge factor (CMD signature PIN; a CSC credential PIN where the
/// provider requires one) consumed by this single call — it is passed straight to the provider and
/// is **never** copied into the returned [`RemoteSignSession`]. Hold it in [`Zeroizing`] at the call
/// site so it is wiped from memory when dropped (SIG-02; t57 ruling 4).
pub struct RemoteInitiate<'a> {
    /// The signer's public account reference at the provider. CMD: the citizen mobile in SCMD
    /// format (`+351 XXXXXXXXX`); a CSC QTSP: the user / credential reference. Non-secret.
    pub user_ref: &'a str,
    /// The signer's secret knowledge factor for this signature (CMD signature PIN; a CSC credential
    /// PIN). **Transient — never persisted.** May be an empty string for providers that carry no
    /// PIN (e.g. a user-OAuth CSC flow where activation is entirely out-of-band).
    pub credential: &'a Zeroizing<String>,
    /// A human-readable document label shown on the signer's device.
    pub doc_name: &'a str,
    /// The fixed signing time. It MUST be carried unchanged into [`RemoteSignSession::signing_time`]
    /// and reused at [`RemoteSigningSource::confirm`] time; the CAdES signed attributes are rebuilt
    /// from it, so a drift would make the signature invalid.
    pub signing_time: OffsetDateTime,
}

/// The **non-secret**, resumable handle bridging a remote provider's two-request flow (t59 F1).
///
/// Produced by [`RemoteSigningSource::initiate`] and consumed by [`RemoteSigningSource::confirm`].
/// It is safe to persist between the two requests (it derives `Serialize`/`Deserialize`): every
/// field is public signature material or correlation state — **never** the PIN or the activation
/// data (OTP / SAD). The completion credential is a transient argument to `confirm`, not a field
/// here (SIG-02; t57 ruling 4).
///
/// The field set generalizes t57's `CmdSignSession` (CMD's `ProcessId` becomes the generic
/// [`Self::provider_ref`], the citizen mobile becomes [`Self::user_ref`]) and gains a
/// [`Self::provider_id`] so an api holding `dyn RemoteSigningSource` can attribute a resumed session
/// to the provider that opened it. Fields are public so downstream provider crates (e.g.
/// `chancela-csc`) can construct it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSignSession {
    /// The stable id of the provider that opened this session (e.g. `"cmd"`, `"multicert"`,
    /// `"digitalsign"`). The api uses it to route `confirm` back to the same provider and to label
    /// the produced artifact; it is the *resolved* provider, never a client-asserted value.
    pub provider_id: String,
    /// The provider-side correlation reference for the pending signature. CMD: the SCMD `ProcessId`;
    /// a CSC QTSP: the credential / authorization reference returned by `credentials/authorize`.
    /// Non-secret.
    pub provider_ref: String,
    /// The signer's public account reference at the provider (CMD: the citizen mobile). A public
    /// identifier — **not** a credential — retained because a provider may re-key its confirm call
    /// by it.
    pub user_ref: String,
    /// The signer's leaf certificate (DER) resolved at initiate. The signed attributes were hashed
    /// over *this* certificate, so [`RemoteSigningSource::confirm`] reassembles the CMS with it (not
    /// any re-fetched copy) to guarantee the attributes reproduce the digest the provider signed.
    pub signing_cert_der: Vec<u8>,
    /// The issuer chain above the leaf (DER, leaf excluded), for CMS assembly and trust resolution.
    pub chain_der: Vec<Vec<u8>>,
    /// The trusted-list status of the signer's issuer resolved at initiate (SIG-11/23), if a policy
    /// was consulted. Only [`TrustedListStatus::Granted`] passes the gate.
    pub trusted_list_status: Option<TrustedListStatus>,
    /// The PAdES `/ByteRange` digest this signature covers — the "prepared" digest linking this
    /// session to its [`PreparedSignature`]. Non-secret.
    pub byterange_digest: [u8; 32],
    /// The fixed signing time carried over from [`RemoteInitiate`] (identical across both phases).
    #[serde(with = "time::serde::rfc3339")]
    pub signing_time: OffsetDateTime,
}

/// A **remote** qualified-signing source whose signature spans two stateless requests (t59 F1).
///
/// The trait is object-safe: an api layer holds providers as `Box<dyn RemoteSigningSource>` (or
/// `&dyn RemoteSigningSource`) and drives [`Self::initiate`] / [`Self::confirm`] uniformly across
/// Chave Móvel Digital and every CSC-standard QTSP. All methods take `&self`, are non-generic over
/// the transport, and fail with the crate-wide [`SigningError`].
///
/// Implementors MUST NOT return [`EvidentiaryLevel::OtpConfirmation`] from [`Self::evidentiary_level`]
/// — the activation step is a confirmation, never the artifact (SIG-02).
pub trait RemoteSigningSource {
    /// The signing family this source serves (SIG-01). Remote QTSP adapters report
    /// [`SigningFamily::QualifiedCertificate`]; CMD reports [`SigningFamily::ChaveMovelDigital`].
    fn family(&self) -> SigningFamily;

    /// The evidentiary level a signature from this source carries (SIG-01) — always
    /// [`EvidentiaryLevel::Qualified`] for a genuine remote QES, **never**
    /// [`EvidentiaryLevel::OtpConfirmation`] (SIG-02).
    fn evidentiary_level(&self) -> EvidentiaryLevel;

    /// **Phase 1.** Authenticate, resolve the signer certificate (+chain), gate it against the
    /// trusted list when a `policy` is supplied (SIG-11/23), take `prepared`'s ByteRange digest, and
    /// open a provider-side signing session — dispatching the activation (OTP / SAD) to the signer.
    /// Returns a secret-free [`RemoteSignSession`] the api persists between the two requests.
    ///
    /// Passing `policy: None` skips the trusted-list gate; the qualified path MUST supply one.
    fn initiate(
        &self,
        req: &RemoteInitiate<'_>,
        prepared: &PreparedSignature,
        policy: Option<&mut dyn TrustPolicy>,
    ) -> Result<RemoteSignSession, SigningError>;

    /// **Phase 2.** Given the session handle and the signer's transient completion credential
    /// (`activation`: the OTP for CMD, the OTP / SAD for a CSC QTSP), submit it to the provider and
    /// assemble the detached CAdES-B CMS over the session's ByteRange digest — the bytes ready to
    /// embed with [`chancela_pades::embed_signature`].
    ///
    /// `activation` is transient: consumed here, never persisted (SIG-02). The CMS is reassembled
    /// from the *session's* certificate/chain and signing time so the attributes reproduce the
    /// digest the provider actually signed.
    fn confirm(
        &self,
        session: &RemoteSignSession,
        activation: &Zeroizing<String>,
    ) -> Result<Vec<u8>, SigningError>;
}
