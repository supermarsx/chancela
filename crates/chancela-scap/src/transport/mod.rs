//! The [`ScapTransport`] boundary plus its [`HttpScapTransport`] (blocking `reqwest`) and
//! fixture-backed [`MockScapTransport`] implementations. The mock is the default and the only
//! transport exercised by tests.
//!
//! ## Compile-time honesty enforcement (t67 §1.2 — binding)
//!
//! [`verify_attribute`](ScapTransport::verify_attribute) returns a [`VerificationDecision`]. Its
//! [`VerificationDecision::Granted`] variant carries an [`AuthoritativeGrant`] witness whose only
//! constructor is **private to the [`http`] module**. The mock lives in the sibling [`mock`] module
//! and therefore *cannot construct the witness* — so it can never return `Granted`, and the client
//! can never turn a mock result into [`crate::ScapVerificationStatus::VerifiedByScap`]. This is a
//! type/module-privacy guarantee, not a runtime convention.

pub mod http;
pub mod mock;

pub use http::{AuthoritativeGrant, HttpScapTransport};
pub use mock::MockScapTransport;

use crate::error::ScapError;
use crate::model::{AttributeProvider, CitizenRef, ProfessionalAttribute};

/// The decision a transport reports when asked to verify a professional-attribute claim.
///
/// Note the asymmetry: only [`Self::Granted`] carries the [`AuthoritativeGrant`] witness, and only
/// [`http`] can mint that witness — see the module docs.
#[non_exhaustive]
pub enum VerificationDecision {
    /// SCAP granted the attribute over the authoritative transport. Carries the granting-authority
    /// witness. **Unconstructable by the mock.**
    Granted(AuthoritativeGrant),
    /// SCAP was consulted over the authoritative transport but did **not** grant the attribute.
    Denied,
    /// The transport is non-authoritative (mock / fixtures): the attribute is declared-only and
    /// was not truly checked against SCAP.
    Declared,
}

/// A synchronous SCAP transport: attribute-provider listing, per-citizen attribute fetch, and
/// per-attribute verification.
///
/// Implementors MUST NOT log credentials or the raw request/response bodies (they may carry
/// AMA credential material). Only the real [`HttpScapTransport`] touches the network.
pub trait ScapTransport {
    /// List the attribute providers SCAP knows about.
    fn list_providers(&self) -> Result<Vec<AttributeProvider>, ScapError>;

    /// Fetch the professional attributes SCAP reports for `citizen`. These are *claims* — on their
    /// own they are declared, not verified.
    fn fetch_attributes(
        &self,
        citizen: &CitizenRef,
    ) -> Result<Vec<ProfessionalAttribute>, ScapError>;

    /// Verify that `citizen` holds `attribute`, returning the transport's decision.
    fn verify_attribute(
        &self,
        attribute: &ProfessionalAttribute,
        citizen: &CitizenRef,
    ) -> Result<VerificationDecision, ScapError>;
}
