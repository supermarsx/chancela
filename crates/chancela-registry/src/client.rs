//! The one-call [`RegistryClient`] (fetch via transport, then parse).

use crate::code::AccessCode;
use crate::error::RegistryError;
use crate::model::RegistryExtract;
use crate::parse::parse_certidao;
use crate::transport::RegistryTransport;

/// Ties a [`RegistryTransport`] to [`parse_certidao`]: one call consults the registry and returns a
/// parsed extract, masking the code into provenance (LEG-22).
#[derive(Debug, Clone)]
pub struct RegistryClient<T: RegistryTransport> {
    transport: T,
}

impl<T: RegistryTransport> RegistryClient<T> {
    /// Build a client over `transport`.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Fetch via the transport, then parse. The full code is used only to fetch; provenance carries
    /// its **masked** form and never the digits.
    pub fn lookup(
        &self,
        code: &AccessCode,
        email: Option<&str>,
    ) -> Result<RegistryExtract, RegistryError> {
        let document = self.transport.fetch(code, email)?;
        parse_certidao(
            &document.html,
            &code.masked(),
            &document.source_url,
            &document.retrieved_at,
        )
    }
}
