//! The trusted-list policy gate (SIG-11/23).
//!
//! Before a qualified signature is trusted, the signer's issuing CA must be a currently-granted
//! QTSP for e-signatures on the Portuguese Trusted List. [`TrustPolicy`] abstracts that decision so
//! the envelope engine stays testable offline: [`TslTrustPolicy`] resolves it against a live/parsed
//! TSL via `chancela-tsl`, while [`StaticTrustPolicy`] returns a fixed status in tests.

use time::OffsetDateTime;

use chancela_tsl::{TslClient, TslSource};

use crate::{SigningError, TrustedListStatus};

/// Resolves whether a signer's issuer is currently trusted for qualified e-signatures (SIG-11/23).
///
/// Object-safe: the envelope engine holds it as `&mut dyn TrustPolicy` (mutable because a real TSL
/// client refreshes its cache on lookup).
pub trait TrustPolicy {
    /// The trusted-list status of `issuer_cert_der` (the signer's issuing-CA certificate) as of
    /// `now`.
    fn issuer_status(
        &mut self,
        issuer_cert_der: &[u8],
        now: OffsetDateTime,
    ) -> Result<TrustedListStatus, SigningError>;
}

/// A [`TrustPolicy`] backed by the real Portuguese Trusted List via a `chancela-tsl`
/// [`TslClient`]. The `chancela-tsl` [`chancela_tsl::QualifiedStatus`] maps 1:1 onto
/// [`TrustedListStatus`] (t4-e5).
pub struct TslTrustPolicy<S: TslSource> {
    client: TslClient<S>,
}

impl<S: TslSource> TslTrustPolicy<S> {
    /// Build a policy over a TSL source (its own cache starts empty and is filled on first query).
    pub fn new(source: S) -> Self {
        Self {
            client: TslClient::new(source),
        }
    }

    /// Build a policy over an already-constructed [`TslClient`].
    pub fn from_client(client: TslClient<S>) -> Self {
        Self { client }
    }

    /// Borrow the underlying client.
    pub fn client(&self) -> &TslClient<S> {
        &self.client
    }
}

impl<S: TslSource> TrustPolicy for TslTrustPolicy<S> {
    fn issuer_status(
        &mut self,
        issuer_cert_der: &[u8],
        now: OffsetDateTime,
    ) -> Result<TrustedListStatus, SigningError> {
        let status = self
            .client
            .is_qualified_for_esig(issuer_cert_der, now)
            .map_err(|e| SigningError::TrustedList(e.to_string()))?;
        Ok(status.into())
    }
}

/// A [`TrustPolicy`] that always returns a fixed status, for offline tests and for callers that
/// resolve trust out-of-band.
#[derive(Debug, Clone, Copy)]
pub struct StaticTrustPolicy {
    status: TrustedListStatus,
}

impl StaticTrustPolicy {
    /// A policy that always reports `status`.
    pub fn new(status: TrustedListStatus) -> Self {
        Self { status }
    }

    /// A policy that always reports [`TrustedListStatus::Granted`].
    pub fn granted() -> Self {
        Self::new(TrustedListStatus::Granted)
    }

    /// A policy that always reports [`TrustedListStatus::Withdrawn`].
    pub fn withdrawn() -> Self {
        Self::new(TrustedListStatus::Withdrawn)
    }
}

impl TrustPolicy for StaticTrustPolicy {
    fn issuer_status(
        &mut self,
        _issuer_cert_der: &[u8],
        _now: OffsetDateTime,
    ) -> Result<TrustedListStatus, SigningError> {
        Ok(self.status)
    }
}
